import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import Petrel
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanSpacesWire
import SwanStorage

/// The narrow capability for the proposal-0016 writer-discovery and
/// notification endpoints. It has no repository-value access and is formed
/// only after the server has selected a startup-preopened account directory.
public struct SwanAuthenticatedSpaceNotificationsCapability: Sendable {
    let directory: any AuthorizedSpaceNotificationDirectory
    let credentialAuthorizer: any SpaceCredentialAuthorizationVerifier
    let serviceAuthentication: any SpaceServiceAuthenticationVerifier
    let recipientBindings: SwanSpaceNotificationRecipientBindings

    init(
        directory: any AuthorizedSpaceNotificationDirectory,
        credentialAuthorizer: any SpaceCredentialAuthorizationVerifier,
        serviceAuthentication: any SpaceServiceAuthenticationVerifier,
        recipientBindings: SwanSpaceNotificationRecipientBindings
    ) {
        self.directory = directory
        self.credentialAuthorizer = credentialAuthorizer
        self.serviceAuthentication = serviceAuthentication
        self.recipientBindings = recipientBindings
    }
}

private enum AuthenticatedSpaceNotificationFailure: Error {
    case invalidRequest
    case spaceNotFound
    case denied
    case unavailable
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
                        rev: $0.wireRevision,
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

private struct AuthenticatedRegisterSpaceNotifyHandler:
    ComAtprotoSpaceRegisterNotify.ServerHandler
{
    typealias Context = Request

    let capability: SwanAuthenticatedSpaceNotificationsCapability

    func handle(
        parameters: Void,
        input: ComAtprotoSpaceRegisterNotify.Input,
        context request: Request
    ) async throws -> ComAtprotoSpaceRegisterNotify.Output {
        let space = try notificationSpace(input.space)
        let authorization = try await credentialAuthorization(
            capability,
            request: request,
            space: space
        )
        let now = Date()
        let expiry = now.addingTimeInterval(SwanSpaceNotificationHTTP.registrationLifetime)
        do {
            try await capability.directory.registerSpaceNotification(
                .init(
                    space: space,
                    endpoint: input.endpoint.uriString(),
                    repository: input.repo?.didString(),
                    expiresAt: expiry
                ),
                authorization: authorization
            )
            return .init(expiresAt: ATProtocolDate(date: expiry))
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
        guard input.hash.data.count == 32,
              (try? TID(tidString: input.rev)) != nil else {
            throw AuthenticatedSpaceNotificationFailure.invalidRequest
        }
        let service = try await serviceAuthentication(
            capability,
            request: request,
            expectedAudience: nil,
            expectedMethod: ComAtprotoSpaceNotifyWrite.typeIdentifier
        )
        // This is the only notifyWrite shape accepted by the pinned TypeScript
        // PDS: the writer signs its own announcement and addresses the space
        // authority. An authority cannot safely re-sign another writer's
        // announcement, so Swan does not claim authority-to-recipient write
        // fanout interoperability on this endpoint.
        guard service.issuer == input.repo.didString(),
              service.audience == space.authority else {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        do {
            try await capability.directory.receiveSpaceWriteNotification(
                .init(
                    eventID: service.eventID,
                    space: space,
                    repository: input.repo.didString(),
                    wireRevision: input.rev,
                    commitment: input.hash.data,
                    issuer: service.issuer,
                    audience: service.audience
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
        let service = try await serviceAuthentication(
            capability,
            request: request,
            expectedAudience: nil,
            expectedMethod: ComAtprotoSpaceNotifySpaceDeleted.typeIdentifier
        )
        guard service.issuer == space.authority else {
            throw AuthenticatedSpaceNotificationFailure.denied
        }
        // A deletion receiver identity is an explicit operator binding rather
        // than a syntactic DID check. This supports the pinned PDS's service
        // identities (which may be endpoint-like) while ensuring an incoming
        // audience cannot select an arbitrary local account.
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
                eventID: service.eventID
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
    capability: SwanAuthenticatedSpaceNotificationsCapability
) {
    let handler = AuthenticatedRegisterSpaceNotifyHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.registerNotify"
    router.post(path) { request, _ async -> Response in
        do {
            let input = try await decodeRegisterSpaceNotifyInput(request)
            let output = try await handler.handle(parameters: (), input: input, context: request)
            return authenticatedGetSpaceJSON(.ok, output)
        } catch let failure as AuthenticatedSpaceNotificationFailure {
            return authenticatedSpaceNotificationResponse(for: failure)
        } catch {
            return authenticatedSpaceNotificationError(.badRequest, code: "InvalidRequest")
        }
    }
    registerAuthenticatedNotificationWrongMethods(on: router, path: path, allowed: .post)
}

func registerAuthenticatedNotifySpaceWriteEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceNotificationsCapability
) {
    let handler = AuthenticatedNotifySpaceWriteHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.notifyWrite"
    router.post(path) { request, _ async -> Response in
        do {
            let input = try await decodeNotifySpaceWriteInput(request)
            try await handler.handle(parameters: (), input: input, context: request)
            return Response(status: .ok, headers: [.cacheControl: "no-store"])
        } catch let failure as AuthenticatedSpaceNotificationFailure {
            return authenticatedSpaceNotificationResponse(for: failure)
        } catch {
            return authenticatedSpaceNotificationError(.badRequest, code: "InvalidRequest")
        }
    }
    registerAuthenticatedNotificationWrongMethods(on: router, path: path, allowed: .post)
}

func registerAuthenticatedNotifySpaceDeletedEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceNotificationsCapability
) {
    let handler = AuthenticatedNotifySpaceDeletedHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.notifySpaceDeleted"
    router.post(path) { request, _ async -> Response in
        do {
            let input = try await decodeNotifySpaceDeletedInput(request)
            try await handler.handle(parameters: (), input: input, context: request)
            return Response(status: .ok, headers: [.cacheControl: "no-store"])
        } catch let failure as AuthenticatedSpaceNotificationFailure {
            return authenticatedSpaceNotificationResponse(for: failure)
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
        let space = try ATProtocolURI(uriString: rawSpace)
        _ = try SpaceURI(space.uriString())
        return .init(space: space, limit: limit, cursor: values["cursor"])
    } catch {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
}

private func decodeRegisterSpaceNotifyInput(
    _ request: Request
) async throws -> ComAtprotoSpaceRegisterNotify.Input {
    let data = try await notificationJSONBody(request)
    try notificationJSONObject(
        data,
        allowedKeys: ["space", "repo", "endpoint"],
        requiredKeys: ["space", "endpoint"]
    )
    do {
        let input = try JSONDecoder().decode(ComAtprotoSpaceRegisterNotify.Input.self, from: data)
        _ = try notificationSpace(input.space)
        if let repository = input.repo {
            _ = try DID(didString: repository.didString())
        }
        guard validRegisteredNotificationEndpoint(input.endpoint.uriString()) else {
            throw AuthenticatedSpaceNotificationFailure.invalidRequest
        }
        return input
    } catch let failure as AuthenticatedSpaceNotificationFailure {
        throw failure
    } catch {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
}

private func decodeNotifySpaceWriteInput(
    _ request: Request
) async throws -> ComAtprotoSpaceNotifyWrite.Input {
    let data = try await notificationJSONBody(request)
    try notificationJSONObject(
        data,
        allowedKeys: ["space", "repo", "rev", "hash"],
        requiredKeys: ["space", "repo", "rev", "hash"]
    )
    do {
        let input = try JSONDecoder().decode(ComAtprotoSpaceNotifyWrite.Input.self, from: data)
        _ = try notificationSpace(input.space)
        _ = try DID(didString: input.repo.didString())
        guard (try? TID(tidString: input.rev)) != nil,
              input.hash.data.count == 32 else {
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
    _ request: Request
) async throws -> ComAtprotoSpaceNotifySpaceDeleted.Input {
    let data = try await notificationJSONBody(request)
    try notificationJSONObject(data, allowedKeys: ["space"], requiredKeys: ["space"])
    do {
        let input = try JSONDecoder().decode(ComAtprotoSpaceNotifySpaceDeleted.Input.self, from: data)
        _ = try notificationSpace(input.space)
        return input
    } catch {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
}

private func notificationJSONBody(_ request: Request) async throws -> Data {
    let contentTypes = request.headers[values: .contentType]
    guard contentTypes.count == 1,
          contentTypes[0]
            .split(separator: ";", maxSplits: 1).first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() == "application/json" else {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
    let lengths = request.headers[values: .contentLength]
    guard lengths.count <= 1,
          lengths.first.flatMap(Int.init).map({
              (1 ... SwanSpaceNotificationHTTP.maximumJSONBytes).contains($0)
          }) ?? true else {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
    let body: ByteBuffer
    do {
        body = try await request.body.collect(upTo: SwanSpaceNotificationHTTP.maximumJSONBytes)
    } catch {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
    guard body.readableBytes > 0,
          let bytes = body.getBytes(at: body.readerIndex, length: body.readableBytes) else {
        throw AuthenticatedSpaceNotificationFailure.invalidRequest
    }
    return Data(bytes)
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

private func notificationSpace(_ value: ATProtocolURI) throws -> SpaceURI {
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
        guard let bearer = try exactBearerToken(from: request.headers) else {
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
    expectedMethod: String
) async throws -> VerifiedSpaceServiceAuthentication {
    let compact: String
    do {
        compact = try exactSpaceServiceBearerToken(from: request.headers)
        return try await capability.serviceAuthentication.authenticate(
            compact,
            expectedAudience: expectedAudience,
            expectedMethod: expectedMethod,
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
    let values = headers[values: .authorization]
    guard values.count == 1,
          let raw = values.first else {
        throw SwanError.unauthorized("service authentication is invalid")
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
