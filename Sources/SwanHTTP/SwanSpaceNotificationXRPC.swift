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
    let directory: any AuthorizedSpaceNotificationDirectory
    let credentialAuthorizer: any SpaceCredentialAuthorizationVerifier
    let serviceAuthentication: any SpaceServiceAuthenticationVerifier
    let recipientBindings: SwanSpaceNotificationRecipientBindings
    let notificationJSONDecodeObserver: (@Sendable () async -> Void)?
    /// Resolves a `registerNotify` subscriber's `service` identifier to its
    /// DID-document endpoint (Erratum 03). `nil` when the server runs without
    /// outbound DID resolution — `service` registrations then answer the same
    /// `ServiceNotResolvable` as an identifier that does not resolve, because
    /// from the caller's seat that is exactly what it is.
    let serviceEndpointResolver: SwanServiceEndpointResolver?

    init(
        directory: any AuthorizedSpaceNotificationDirectory,
        credentialAuthorizer: any SpaceCredentialAuthorizationVerifier,
        serviceAuthentication: any SpaceServiceAuthenticationVerifier,
        recipientBindings: SwanSpaceNotificationRecipientBindings,
        notificationJSONDecodeObserver: (@Sendable () async -> Void)? = nil,
        serviceEndpointResolver: SwanServiceEndpointResolver? = nil
    ) {
        self.directory = directory
        self.credentialAuthorizer = credentialAuthorizer
        self.serviceAuthentication = serviceAuthentication
        self.recipientBindings = recipientBindings
        self.notificationJSONDecodeObserver = notificationJSONDecodeObserver
        self.serviceEndpointResolver = serviceEndpointResolver
    }
}

private enum AuthenticatedSpaceNotificationFailure: Error {
    case invalidRequest
    case spaceNotFound
    case denied
    case unavailable
    /// The `service` identifier could not be resolved to a DID document with
    /// a usable service endpoint (Erratum 03). The lexicon's one named error
    /// for it; the underlying cause is logged, never returned — a 500 would
    /// implicate the server in what is usually a typo'd DID.
    case serviceNotResolvable
}

private enum SwanSpaceNotificationHTTP {
    /// Writer metadata and compact service tokens are control-plane inputs.
    /// Keeping this much smaller than a record write also prevents the route
    /// from turning into a generic buffered upload surface.
    static let maximumJSONBytes = 16 * 1_024
    static let maximumQueryBytes = 4 * 1_024
    static let maximumListLimit = 1_000
    static let registrationLifetime: TimeInterval = 24 * 60 * 60
}

private struct AuthenticatedListSpaceReposHandler:
    ComAtprotoSpaceListRepos.ServerHandler
{
    typealias Context = Request

    let capability: SwanAuthenticatedSpaceNotificationsCapability

    func handle(
        parameters: ComAtprotoSpaceListRepos.Parameters,
        input: Void,
        context request: Request
    ) async throws -> ComAtprotoSpaceListRepos.Output {
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
            return .init(
                cursor: writers.last?.repository,
                repos: try writers.map {
                    .init(
                        did: try DID(didString: $0.repository),
                        rev: try TID(tidString: $0.wireRevision),
                        hash: Bytes(data: $0.commitment)
                    )
                }
            )
        } catch {
            // The directory must already have validated these identifiers;
            // treating an impossible projection mismatch as unavailable does
            // not expose its internal state to the client.
            throw AuthenticatedSpaceNotificationFailure.unavailable
        }
    }
}

/// The `registerNotify` wire input. `service` names the subscriber (a DID
/// with an optional `#fragment`, resolved through its DID document — the
/// current lexicon shape); `endpoint` is the pre-lexicon legacy. At least one
/// is required, and when both are sent `service` decides, mirroring the
/// reference handler.
private struct RegisterSpaceNotifyWireInput: Decodable {
    let space: SpaceRef
    let repo: DID?
    let endpoint: String?
    let service: String?
}

private struct AuthenticatedRegisterSpaceNotifyHandler {
    let capability: SwanAuthenticatedSpaceNotificationsCapability

    func handle(
        parameters _: Void,
        input: RegisterSpaceNotifyWireInput,
        context request: Request
    ) async throws -> ComAtprotoSpaceRegisterNotify.Output {
        let space = try notificationSpace(input.space)
        let authorization = try await credentialAuthorization(
            capability,
            request: request,
            space: space
        )
        let serviceToken: String
        do {
            serviceToken = try exactAtprotoServiceAuthBearerToken(from: request.headers)
        } catch {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        let authenticatedService: VerifiedSpaceServiceAuthentication
        do {
            authenticatedService = try await capability.serviceAuthentication.authenticate(
                serviceToken,
                expectedAudience: space.authority,
                expectedMethod: ComAtprotoSpaceRegisterNotify.typeIdentifier,
                expectedRequestBodyDigest: nil,
                now: Date()
            )
        } catch let error as SwanError {
            if case .unavailable = error {
                throw AuthenticatedSpaceNotificationFailure.unavailable
            }
            throw AuthenticatedSpaceNotificationFailure.denied
        } catch {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        let ownerDID = authenticatedService.issuer
        if let requested = input.service {
            guard requested == ownerDID || serviceIssuerDID(requested) == ownerDID else {
                throw AuthenticatedSpaceNotificationFailure.denied
            }
        }
        let endpoint: String
        let service: String?
        if let identifier = input.service {
            guard let resolver = capability.serviceEndpointResolver else {
                throw AuthenticatedSpaceNotificationFailure.serviceNotResolvable
            }
            let resolved: URL
            do {
                resolved = try await resolver.endpoint(serviceIdentifier: identifier)
            } catch {
                throw AuthenticatedSpaceNotificationFailure.serviceNotResolvable
            }
            endpoint = resolved.absoluteString
            service = identifier
        } else if let supplied = input.endpoint {
            endpoint = supplied
            service = nil
        } else {
            throw AuthenticatedSpaceNotificationFailure.invalidRequest
        }
        let now = Date()
        let expiry = now.addingTimeInterval(SwanSpaceNotificationHTTP.registrationLifetime)
        do {
            try await capability.directory.registerSpaceNotification(
                .init(
                    space: space,
                    endpoint: endpoint,
                    repository: input.repo?.didString(),
                    expiresAt: expiry,
                    service: service,
                    serviceDID: ownerDID
                ),
                serviceDID: ownerDID,
                authorization: authorization
            )
            return .init(expiresAt: ATProtocolDate(date: expiry))
        } catch {
            throw notificationStorageFailure(error)
        }
    }
}

private struct AuthenticatedUnregisterSpaceNotifyHandler {
    let capability: SwanAuthenticatedSpaceNotificationsCapability

    func handle(
        parameters _: Void,
        input: ComAtprotoSpaceUnregisterNotify.Input,
        context request: Request
    ) async throws {
        let space = try notificationSpace(input.space)
        let authorization = try await credentialAuthorization(
            capability, request: request, space: space
        )
        let serviceToken: String
        do {
            serviceToken = try exactAtprotoServiceAuthBearerToken(from: request.headers)
        } catch {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        let authenticatedService: VerifiedSpaceServiceAuthentication
        do {
            authenticatedService = try await capability.serviceAuthentication.authenticate(
                serviceToken,
                expectedAudience: space.authority,
                expectedMethod: ComAtprotoSpaceUnregisterNotify.typeIdentifier,
                expectedRequestBodyDigest: nil,
                now: Date()
            )
        } catch let error as SwanError {
            if case .unavailable = error {
                throw AuthenticatedSpaceNotificationFailure.unavailable
            }
            throw AuthenticatedSpaceNotificationFailure.denied
        } catch {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        let ownerDID = authenticatedService.issuer
        guard input.service == ownerDID || serviceIssuerDID(input.service) == ownerDID else {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        do {
            try await capability.directory.unregisterSpaceNotification(
                space: space,
                ownerServiceDID: ownerDID,
                deliveryServiceDID: input.service,
                authorization: authorization
            )
        } catch {
            throw notificationStorageFailure(error)
        }
    }
}

private struct AuthenticatedNotifySpaceWriteHandler:
    ComAtprotoSpaceNotifyWrite.ServerHandler
{
    typealias Context = Request
    let capability: SwanAuthenticatedSpaceNotificationsCapability

    func handle(
        parameters: Void,
        input: ComAtprotoSpaceNotifyWrite.Input,
        context request: Request
    ) async throws {
        let space = try notificationSpace(input.space)
        guard input.hash.data.count == 32 else {
            throw AuthenticatedSpaceNotificationFailure.invalidRequest
        }
        let expectedDigest = SpaceNotificationRequestDigest.write(
            space: space,
            repository: input.repo.didString(),
            wireRevision: input.rev.toString(),
            commitment: input.hash.data
        )
        let service = try await serviceAuthentication(
            capability,
            request: request,
            expectedAudience: space.authority,
            expectedMethod: ComAtprotoSpaceNotifyWrite.typeIdentifier,
            expectedRequestBodyDigest: expectedDigest
        )
        guard service.issuer == input.repo.didString(),
              service.audience == space.authority,
              let verifiedDigest = service.requestBodyDigest,
              verifiedDigest == expectedDigest else {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        do {
            try await capability.directory.receiveSpaceWriteNotification(
                .init(
                    eventID: service.eventID,
                    space: space,
                    repository: input.repo.didString(),
                    wireRevision: input.rev.toString(),
                    commitment: input.hash.data,
                    issuer: service.issuer,
                    audience: service.audience,
                    requestBodyDigest: verifiedDigest
                )
            )
        } catch {
            throw notificationStorageFailure(error)
        }
    }
}

private struct AuthenticatedNotifySpaceDeletedHandler:
    ComAtprotoSpaceNotifySpaceDeleted.ServerHandler
{
    typealias Context = Request

    let capability: SwanAuthenticatedSpaceNotificationsCapability

    func handle(
        parameters: Void,
        input: ComAtprotoSpaceNotifySpaceDeleted.Input,
        context request: Request
    ) async throws {
        let space = try notificationSpace(input.space)
        let expectedDigest = SpaceNotificationRequestDigest.deletion(space: space)
        let service = try await serviceAuthentication(
            capability,
            request: request,
            expectedAudience: nil,
            expectedMethod: ComAtprotoSpaceNotifySpaceDeleted.typeIdentifier,
            expectedRequestBodyDigest: expectedDigest
        )
        guard service.issuer == space.authority,
              let verifiedDigest = service.requestBodyDigest,
              verifiedDigest == expectedDigest else {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        guard let recipientAccount = capability.recipientBindings.account(
            forServiceIdentity: service.audience
        ) else {
            return
        }
        do {
            try await capability.directory.receiveSpaceDeletionNotification(
                space: space,
                issuer: service.issuer,
                audience: recipientAccount,
                eventID: service.eventID,
                requestBodyDigest: verifiedDigest
            )
        } catch {
            throw notificationStorageFailure(error)
        }
    }
}


func registerAuthenticatedListSpaceReposEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceNotificationsCapability
) {
    let handler = AuthenticatedListSpaceReposHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.listRepos"
    router.get(path) { request, _ async -> Response in
        do {
            let parameters = try parseListSpaceReposParameters(request)
            let output = try await handler.handle(parameters: parameters, input: (), context: request)
            return authenticatedGetSpaceJSON(.ok, output)
        } catch let failure as AuthenticatedSpaceNotificationFailure {
            return authenticatedSpaceNotificationResponse(for: failure)
        } catch {
            return authenticatedSpaceNotificationError(.badRequest, code: "InvalidRequest")
        }
    }
    registerAuthenticatedNotificationWrongMethods(on: router, path: path, allowed: .get)
}

func registerAuthenticatedRegisterSpaceNotifyEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceNotificationsCapability,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) {
    let handler = AuthenticatedRegisterSpaceNotifyHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.registerNotify"
    router.post(path) { request, context async -> Response in
        do {
            let input = try await decodeRegisterSpaceNotifyInput(
                request, context: context, requestBodyAdmission: requestBodyAdmission,
                decodeObserver: capability.notificationJSONDecodeObserver)
            let output = try await handler.handle(parameters: (), input: input, context: request)
            return authenticatedGetSpaceJSON(.ok, output)
        } catch let failure as AuthenticatedSpaceNotificationFailure {
            // Rejection KIND only — never body content. Tonight's debugging
            // repeatedly stalled on silent 400s from this route.
            context.logger.info(
                "registerNotify rejected",
                metadata: ["failure": .string(String(describing: failure))]
            )
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

func registerAuthenticatedUnregisterSpaceNotifyEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceNotificationsCapability,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) {
    let handler = AuthenticatedUnregisterSpaceNotifyHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.unregisterNotify"
    router.post(path) { request, context async -> Response in
        do {
            let input = try await decodeUnregisterSpaceNotifyInput(
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

func registerAuthenticatedNotifySpaceWriteEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceNotificationsCapability,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) {
    let handler = AuthenticatedNotifySpaceWriteHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.notifyWrite"
    router.post(path) { request, context async -> Response in
        do {
            let input = try await decodeNotifySpaceWriteInput(
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

func registerAuthenticatedNotifySpaceDeletedEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceNotificationsCapability,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) {
    let handler = AuthenticatedNotifySpaceDeletedHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.notifySpaceDeleted"
    router.post(path) { request, context async -> Response in
        do {
            let input = try await decodeNotifySpaceDeletedInput(
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

private func parseListSpaceReposParameters(
    _ request: Request
) throws -> ComAtprotoSpaceListRepos.Parameters {
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
    if let cursor = values["cursor"] {
        guard (try? DID(didString: cursor)) != nil else {
            throw AuthenticatedSpaceNotificationFailure.invalidRequest
        }
    }
    do {
        let space = try SpaceRef(uriString: rawSpace)
        _ = try SpaceURI(space.uriString())
        return .init(space: space, limit: limit, cursor: values["cursor"])
    } catch {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
}

private func decodeRegisterSpaceNotifyInput(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration,
    decodeObserver: (@Sendable () async -> Void)?
) async throws -> RegisterSpaceNotifyWireInput {
    let admitted = try await notificationJSONBody(
        request, context: context, requestBodyAdmission: requestBodyAdmission)
    defer { withExtendedLifetime(admitted.body) {} }
    let data = admitted.data
    await decodeObserver?()
    try notificationJSONObject(
        data,
        allowedKeys: ["space", "repo", "endpoint", "service"],
        requiredKeys: ["space"]
    )
    do {
        let input = try JSONDecoder().decode(RegisterSpaceNotifyWireInput.self, from: data)
        _ = try notificationSpace(input.space)
        if let repository = input.repo {
            _ = try DID(didString: repository.didString())
        }
        // At least one subscriber locator; `service` decides when both are
        // sent (the handler ignores `endpoint` in that case).
        guard input.service != nil || input.endpoint != nil else {
            throw AuthenticatedSpaceNotificationFailure.invalidRequest
        }
        if let service = input.service {
            guard validNotificationServiceIdentifier(service) else {
                throw AuthenticatedSpaceNotificationFailure.invalidRequest
            }
        }
        if input.service == nil, let endpoint = input.endpoint {
            guard validRegisteredNotificationEndpoint(endpoint) else {
                throw AuthenticatedSpaceNotificationFailure.invalidRequest
            }
        }
        return input
    } catch let failure as AuthenticatedSpaceNotificationFailure {
        throw failure
    } catch {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
}

private func decodeUnregisterSpaceNotifyInput(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration,
    decodeObserver: (@Sendable () async -> Void)?
) async throws -> ComAtprotoSpaceUnregisterNotify.Input {
    let admitted = try await notificationJSONBody(
        request, context: context, requestBodyAdmission: requestBodyAdmission)
    defer { withExtendedLifetime(admitted.body) {} }
    let data = admitted.data
    await decodeObserver?()
    try notificationJSONObject(
        data,
        allowedKeys: ["space", "service"],
        requiredKeys: ["space", "service"]
    )
    do {
        let input = try JSONDecoder().decode(ComAtprotoSpaceUnregisterNotify.Input.self, from: data)
        _ = try notificationSpace(input.space)
        guard validNotificationServiceIdentifier(input.service) else {
            throw AuthenticatedSpaceNotificationFailure.invalidRequest
        }
        return input
    } catch let failure as AuthenticatedSpaceNotificationFailure {
        throw failure
    } catch {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
}

/// A subscriber service identifier: `did:<method>:…` with at most one
/// non-empty `#fragment`, printable ASCII, bounded. Resolution decides
/// everything further — this only refuses shapes that could never name a
/// verifiable audience.
private func validNotificationServiceIdentifier(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 640,
          value.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }) else {
        return false
    }
    let parts = value.split(separator: "#", omittingEmptySubsequences: false)
    guard (1 ... 2).contains(parts.count),
          parts.allSatisfy({ !$0.isEmpty }),
          parts[0].hasPrefix("did:") else {
        return false
    }
    return true
}

private func decodeNotifySpaceWriteInput(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration,
    decodeObserver: (@Sendable () async -> Void)?
) async throws -> ComAtprotoSpaceNotifyWrite.Input {
    let admitted = try await notificationJSONBody(
        request, context: context, requestBodyAdmission: requestBodyAdmission)
    defer { withExtendedLifetime(admitted.body) {} }
    let data = admitted.data
    await decodeObserver?()
    try notificationJSONObject(
        data,
        allowedKeys: ["space", "repo", "rev", "hash"],
        requiredKeys: ["space", "repo", "rev", "hash"]
    )
    do {
        let input = try JSONDecoder().decode(ComAtprotoSpaceNotifyWrite.Input.self, from: data)
        _ = try notificationSpace(input.space)
        _ = try DID(didString: input.repo.didString())
        guard input.hash.data.count == 32 else {
            throw AuthenticatedSpaceNotificationFailure.invalidRequest
        }
        return input
    } catch let failure as AuthenticatedSpaceNotificationFailure {
        throw failure
    } catch {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
}

private func decodeNotifySpaceDeletedInput(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration,
    decodeObserver: (@Sendable () async -> Void)?
) async throws -> ComAtprotoSpaceNotifySpaceDeleted.Input {
    let admitted = try await notificationJSONBody(
        request, context: context, requestBodyAdmission: requestBodyAdmission)
    defer { withExtendedLifetime(admitted.body) {} }
    let data = admitted.data
    await decodeObserver?()
    try notificationJSONObject(data, allowedKeys: ["space"], requiredKeys: ["space"])
    do {
        let input = try JSONDecoder().decode(ComAtprotoSpaceNotifySpaceDeleted.Input.self, from: data)
        _ = try notificationSpace(input.space)
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
        let authorization = try await capability.credentialAuthorizer.authorization(
            for: token,
            expectedSpace: space,
            now: Date()
        )
        guard case let .spaceCredential(grant) = authorization,
              grant.space == space else {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        return authorization
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

func exactAtprotoServiceAuthBearerToken(from headers: HTTPFields) throws -> String {
    let matches = headers.filter {
        $0.name.rawName.caseInsensitiveCompare("atproto-service-auth") == .orderedSame
    }
    guard matches.count == 1,
          let raw = matches.first?.value else {
        throw SwanError.unauthorized("Atproto-Service-Auth header is required")
    }
    let prefix = "Bearer "
    guard raw.count >= prefix.count,
          raw.prefix(prefix.count).caseInsensitiveCompare(prefix) == .orderedSame else {
        throw SwanError.unauthorized("service authentication is invalid")
    }
    let token = String(raw.dropFirst(prefix.count))
    guard !token.isEmpty,
          token.utf8.count <= SpaceServiceJWT.maximumCompactBytes,
          token.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
        throw SwanError.unauthorized("service authentication is invalid")
    }
    return token
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
    case .unavailable:
        authenticatedSpaceNotificationError(.serviceUnavailable, code: "temporarily_unavailable")
    case .serviceNotResolvable:
        authenticatedSpaceNotificationError(.badRequest, code: "ServiceNotResolvable")
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
