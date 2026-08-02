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

/// The internal capability required to publish authority-owned SimpleSpace
/// lifecycle endpoints. `SwanHTTPServer` creates it only from the same fixed
/// DPoP resource authorizer and startup-preopened directory used by the other
/// authenticated space routes.
public struct SwanAuthenticatedSimpleSpaceLifecycleCapability: Sendable {
    let authorizer: SwanOAuthResourceAuthorizer
    let directory: any AuthorizedSimpleSpaceLifecycleDirectory
    let tidAllocator: SwanPermissionedTIDAllocator
    let jsonWriteAdmission: PublicRepositoryJSONWriteAdmission
    let jsonWriteBodyPolicy: SwanJSONWriteBodyPolicy

    init(
        authorizer: SwanOAuthResourceAuthorizer,
        directory: any AuthorizedSimpleSpaceLifecycleDirectory,
        jsonWriteAdmission: PublicRepositoryJSONWriteAdmission = .processShared,
        jsonWriteBodyPolicy: SwanJSONWriteBodyPolicy = .productionDefault
    ) {
        self.authorizer = authorizer
        self.directory = directory
        tidAllocator = SwanPermissionedTIDAllocator()
        self.jsonWriteAdmission = jsonWriteAdmission
        self.jsonWriteBodyPolicy = jsonWriteBodyPolicy
    }
}

private enum AuthenticatedSimpleSpaceLifecycleFailure: Error {
    case invalidRequest
    case spaceNotFound
    case spaceAlreadyExists
    case denied
    case nonceChallenge
    case unavailable
}

private struct AuthenticatedSimpleSpaceCreateHandler: ComAtprotoSimplespaceCreateSpace.ServerHandler {
    typealias Context = Request
    let capability: SwanAuthenticatedSimpleSpaceLifecycleCapability

    func handle(
        parameters: Void,
        input: ComAtprotoSimplespaceCreateSpace.Input,
        context request: Request
    ) async throws -> ComAtprotoSimplespaceCreateSpace.Output {
        let space: SpaceURI
        do {
            let skey: String
            if let supplied = input.skey {
                skey = supplied
            } else {
                skey = try await capability.tidAllocator.next().toString()
            }
            space = try SpaceURI(
                authority: input.did.didString(),
                spaceType: input.type.nsidString(),
                skey: skey
            )
        } catch {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
        let authorization = try await lifecycleAuthorization(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/com.atproto.simplespace.createSpace"
        )
        try requireLifecycleAuthority(authorization, space: space)
        let configuration: SimpleSpaceConfiguration
        do {
            configuration = try simpleSpaceConfiguration(input.config)
        } catch {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
        do {
            try await capability.directory.createSimpleSpace(
                space,
                configuration: configuration,
                authorization: authorization
            )
        } catch {
            throw lifecycleFailure(for: error)
        }
        do {
            return try .init(uri: ATProtocolURI(uriString: space.rawValue))
        } catch {
            throw AuthenticatedSimpleSpaceLifecycleFailure.unavailable
        }
    }
}

private struct AuthenticatedSimpleSpaceUpdateHandler: ComAtprotoSimplespaceUpdateSpace.ServerHandler {
    typealias Context = Request
    let capability: SwanAuthenticatedSimpleSpaceLifecycleCapability

    func handle(
        parameters: Void,
        input: ComAtprotoSimplespaceUpdateSpace.Input,
        context request: Request
    ) async throws {
        let space = try lifecycleSpace(input.space)
        let authorization = try await lifecycleAuthorization(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/com.atproto.simplespace.updateSpace"
        )
        try requireLifecycleAuthority(authorization, space: space)
        let patch: SimpleSpaceConfigurationPatch
        do {
            patch = try simpleSpacePatch(input)
        } catch {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
        do {
            try await capability.directory.updateSimpleSpace(
                space,
                patch: patch,
                authorization: authorization
            )
        } catch {
            throw lifecycleFailure(for: error)
        }
    }
}

private struct AuthenticatedSimpleSpaceDeleteHandler: ComAtprotoSimplespaceDeleteSpace.ServerHandler {
    typealias Context = Request
    let capability: SwanAuthenticatedSimpleSpaceLifecycleCapability

    func handle(
        parameters: Void,
        input: ComAtprotoSimplespaceDeleteSpace.Input,
        context request: Request
    ) async throws {
        let space = try lifecycleSpace(input.space)
        let authorization = try await lifecycleAuthorization(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/com.atproto.simplespace.deleteSpace"
        )
        try requireLifecycleAuthority(authorization, space: space)
        do {
            try await capability.directory.deleteSimpleSpace(space, authorization: authorization)
        } catch {
            throw lifecycleFailure(for: error)
        }
    }
}

private struct AuthenticatedSimpleSpaceAddMemberHandler: ComAtprotoSimplespaceAddMember.ServerHandler {
    typealias Context = Request
    let capability: SwanAuthenticatedSimpleSpaceLifecycleCapability

    func handle(
        parameters: Void,
        input: ComAtprotoSimplespaceAddMember.Input,
        context request: Request
    ) async throws {
        let space = try lifecycleSpace(input.space)
        let member = input.did.didString()
        let authorization = try await lifecycleAuthorization(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/com.atproto.simplespace.addMember"
        )
        try requireLifecycleAuthority(authorization, space: space)
        do {
            try await capability.directory.addSimpleSpaceMember(
                member,
                to: space,
                authorization: authorization
            )
        } catch {
            throw lifecycleFailure(for: error)
        }
    }
}

private struct AuthenticatedSimpleSpaceRemoveMemberHandler: ComAtprotoSimplespaceRemoveMember.ServerHandler {
    typealias Context = Request
    let capability: SwanAuthenticatedSimpleSpaceLifecycleCapability

    func handle(
        parameters: Void,
        input: ComAtprotoSimplespaceRemoveMember.Input,
        context request: Request
    ) async throws {
        let space = try lifecycleSpace(input.space)
        let member = input.did.didString()
        let authorization = try await lifecycleAuthorization(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/com.atproto.simplespace.removeMember"
        )
        try requireLifecycleAuthority(authorization, space: space)
        do {
            try await capability.directory.removeSimpleSpaceMember(
                member,
                from: space,
                authorization: authorization
            )
        } catch {
            throw lifecycleFailure(for: error)
        }
    }
}

private struct AuthenticatedSimpleSpaceListMembersHandler: ComAtprotoSimplespaceListMembers.ServerHandler {
    typealias Context = Request
    let capability: SwanAuthenticatedSimpleSpaceLifecycleCapability

    func handle(
        parameters: ComAtprotoSimplespaceListMembers.Parameters,
        input: Void,
        context request: Request
    ) async throws -> ComAtprotoSimplespaceListMembers.Output {
        let space = try lifecycleSpace(parameters.space)
        let authorization = try await lifecycleAuthorization(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/com.atproto.simplespace.listMembers",
            method: "GET"
        )
        try requireLifecycleAuthority(authorization, space: space)
        let page: AuthorizedSimpleSpaceMemberPage
        do {
            page = try await capability.directory.simpleSpaceMembers(
                space,
                limit: parameters.limit ?? 100,
                cursor: parameters.cursor,
                authorization: authorization
            )
        } catch {
            throw lifecycleFailure(for: error)
        }
        do {
            return try .init(
                cursor: page.cursor,
                members: page.members.map { try .init(did: DID(didString: $0)) }
            )
        } catch {
            throw AuthenticatedSimpleSpaceLifecycleFailure.unavailable
        }
    }
}

func registerAuthenticatedSimpleSpaceLifecycleEndpoints(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSimpleSpaceLifecycleCapability
) {
    registerSimpleSpaceCreate(on: router, capability: capability)
    registerSimpleSpaceUpdate(on: router, capability: capability)
    registerSimpleSpaceDelete(on: router, capability: capability)
    registerSimpleSpaceAddMember(on: router, capability: capability)
    registerSimpleSpaceRemoveMember(on: router, capability: capability)
    registerSimpleSpaceListMembers(on: router, capability: capability)
}

private func registerSimpleSpaceCreate(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSimpleSpaceLifecycleCapability
) {
    let handler = AuthenticatedSimpleSpaceCreateHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.simplespace.createSpace"
    router.post(path) { request, context async -> Response in
        await withSimpleSpaceInput(
            request,
            context: context,
            as: ComAtprotoSimplespaceCreateSpace.Input.self,
            capability: capability,
            required: ["did", "type"],
            allowed: ["did", "type", "skey", "config"]
        ) { input in
            authenticatedGetSpaceJSON(
                .ok,
                try await handler.handle(parameters: (), input: input, context: request)
            )
        }
    }
    registerSimpleSpaceWrongMethods(on: router, path: path, liveMethod: .post)
}

private func registerSimpleSpaceUpdate(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSimpleSpaceLifecycleCapability
) {
    let handler = AuthenticatedSimpleSpaceUpdateHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.simplespace.updateSpace"
    router.post(path) { request, context async -> Response in
        await withSimpleSpaceInput(
            request,
            context: context,
            as: ComAtprotoSimplespaceUpdateSpace.Input.self,
            capability: capability,
            required: ["space"],
            allowed: ["space", "policy", "managingApp", "appAccess"]
        ) { input in
            _ = try await handler.handle(parameters: (), input: input, context: request)
            return Response(status: .ok, headers: [.cacheControl: "no-store"])
        }
    }
    registerSimpleSpaceWrongMethods(on: router, path: path, liveMethod: .post)
}

private func registerSimpleSpaceDelete(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSimpleSpaceLifecycleCapability
) {
    let handler = AuthenticatedSimpleSpaceDeleteHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.simplespace.deleteSpace"
    router.post(path) { request, context async -> Response in
        await withSimpleSpaceInput(
            request,
            context: context,
            as: ComAtprotoSimplespaceDeleteSpace.Input.self,
            capability: capability,
            required: ["space"],
            allowed: ["space"]
        ) { input in
            _ = try await handler.handle(parameters: (), input: input, context: request)
            return Response(status: .ok, headers: [.cacheControl: "no-store"])
        }
    }
    registerSimpleSpaceWrongMethods(on: router, path: path, liveMethod: .post)
}

private func registerSimpleSpaceAddMember(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSimpleSpaceLifecycleCapability
) {
    let handler = AuthenticatedSimpleSpaceAddMemberHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.simplespace.addMember"
    router.post(path) { request, context async -> Response in
        await withSimpleSpaceInput(
            request,
            context: context,
            as: ComAtprotoSimplespaceAddMember.Input.self,
            capability: capability,
            required: ["space", "did"],
            allowed: ["space", "did"]
        ) { input in
            _ = try await handler.handle(parameters: (), input: input, context: request)
            return Response(status: .ok, headers: [.cacheControl: "no-store"])
        }
    }
    registerSimpleSpaceWrongMethods(on: router, path: path, liveMethod: .post)
}

private func registerSimpleSpaceRemoveMember(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSimpleSpaceLifecycleCapability
) {
    let handler = AuthenticatedSimpleSpaceRemoveMemberHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.simplespace.removeMember"
    router.post(path) { request, context async -> Response in
        await withSimpleSpaceInput(
            request,
            context: context,
            as: ComAtprotoSimplespaceRemoveMember.Input.self,
            capability: capability,
            required: ["space", "did"],
            allowed: ["space", "did"]
        ) { input in
            _ = try await handler.handle(parameters: (), input: input, context: request)
            return Response(status: .ok, headers: [.cacheControl: "no-store"])
        }
    }
    registerSimpleSpaceWrongMethods(on: router, path: path, liveMethod: .post)
}

private func registerSimpleSpaceListMembers(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSimpleSpaceLifecycleCapability
) {
    let handler = AuthenticatedSimpleSpaceListMembersHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.simplespace.listMembers"
    router.get(path) { request, _ async -> Response in
        do {
            let parameters = try parseSimpleSpaceListMembersParameters(request)
            let output = try await handler.handle(parameters: parameters, input: (), context: request)
            return simpleSpaceMembersJSON(.ok, output)
        } catch let failure as AuthenticatedSimpleSpaceLifecycleFailure {
            return simpleSpaceLifecycleResponse(for: failure, capability: capability)
        } catch {
            return simpleSpaceLifecycleError(.badRequest, code: "InvalidRequest")
        }
    }
    registerSimpleSpaceWrongMethods(on: router, path: path, liveMethod: .get)
}

private func lifecycleAuthorization(
    _ authorizer: SwanOAuthResourceAuthorizer,
    request: Request,
    fixedPath: String,
    method: String = "POST"
) async throws -> AuthorizationContext {
    do {
        return try await authorizer.authorize(
            request: request,
            method: method,
            fixedPath: fixedPath
        )
    } catch let failure as SwanResourceAuthorizationFailure {
        throw switch failure {
        case .nonceChallengeRequired: AuthenticatedSimpleSpaceLifecycleFailure.nonceChallenge
        case .denied: AuthenticatedSimpleSpaceLifecycleFailure.denied
        case .unavailable: AuthenticatedSimpleSpaceLifecycleFailure.unavailable
        }
    } catch {
        throw AuthenticatedSimpleSpaceLifecycleFailure.unavailable
    }
}

private func requireLifecycleAuthority(
    _ authorization: AuthorizationContext,
    space: SpaceURI
) throws {
    guard case let .accountOAuth(subject, _) = authorization,
          subject == space.authority else {
        // The authority account owns this host-internal state. A foreign
        // token is intentionally indistinguishable from an absent space.
        throw AuthenticatedSimpleSpaceLifecycleFailure.spaceNotFound
    }
}

private func lifecycleSpace(_ uri: ATProtocolURI) throws -> SpaceURI {
    do {
        return try SpaceURI(uri.uriString())
    } catch {
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
}

private func lifecycleFailure(for error: Error) -> AuthenticatedSimpleSpaceLifecycleFailure {
    if error is AuthorizedSimpleSpaceLifecycleError {
        return .spaceNotFound
    }
    guard let error = error as? SwanError else { return .unavailable }
    switch error {
    case .conflict: return .spaceAlreadyExists
    case .unauthorized, .expired: return .denied
    case .invalidIdentifier, .malformed: return .invalidRequest
    case .invalidProfile, .unavailable: return .unavailable
    }
}

private func simpleSpaceConfiguration(
    _ config: ComAtprotoSimplespaceDefs.SpaceConfig?
) throws -> SimpleSpaceConfiguration {
    guard let config else { return try .init() }
    guard let policy = SimpleSpacePolicy(rawValue: config.policy) else {
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
    return try .init(
        policy: policy,
        appAccess: try simpleSpaceAppAccess(config.appAccess),
        managingApp: config.managingApp
    )
}

private func simpleSpacePatch(
    _ input: ComAtprotoSimplespaceUpdateSpace.Input
) throws -> SimpleSpaceConfigurationPatch {
    let policy = try input.policy.map {
        guard let policy = SimpleSpacePolicy(rawValue: $0) else {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
        return policy
    }
    let appAccess = try input.appAccess.map(simpleSpaceAppAccess)
    let managingApp: SimpleSpaceConfigurationPatch.ManagingApp
    if let value = input.managingApp {
        guard value.utf8.count <= 2_048 else {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
        managingApp = .set(value.isEmpty ? nil : value)
    } else {
        managingApp = .unchanged
    }
    return .init(policy: policy, appAccess: appAccess, managingApp: managingApp)
}

private func simpleSpaceAppAccess(
    _ wire: ComAtprotoSimplespaceDefs.SpaceConfigAppAccessUnion
) throws -> SimpleSpaceAppAccess {
    switch wire {
    case .comAtprotoSimplespaceDefsOpen:
        return .open
    case let .comAtprotoSimplespaceDefsAllowList(value):
        guard value.allowed.count <= 1_000 else {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
        return .allowList(Set(value.allowed))
    case .unexpected:
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
}

private func simpleSpaceAppAccess(
    _ wire: ComAtprotoSimplespaceUpdateSpace.InputAppAccessUnion
) throws -> SimpleSpaceAppAccess {
    switch wire {
    case .comAtprotoSimplespaceDefsOpen:
        return .open
    case let .comAtprotoSimplespaceDefsAllowList(value):
        guard value.allowed.count <= 1_000 else {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
        return .allowList(Set(value.allowed))
    case .unexpected:
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
}

private func withSimpleSpaceInput<Value: Decodable>(
    _ request: Request,
    context: SwanHTTPRequestContext,
    as type: Value.Type,
    capability: SwanAuthenticatedSimpleSpaceLifecycleCapability,
    required: Set<String>,
    allowed: Set<String>,
    operation: (Value) async throws -> Response
) async -> Response {
    let contentTypes = request.headers[values: .contentType]
    guard contentTypes.count == 1,
          contentTypes[0].split(separator: ";", maxSplits: 1).first?
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "application/json"
    else {
        context.jsonWriteBodyTermination.terminate()
        return simpleSpaceLifecycleResponse(
            for: .invalidRequest,
            capability: capability
        )
    }
    guard acceptsSimpleSpaceWriteContentLength(request.headers[values: .contentLength]) else {
        context.jsonWriteBodyTermination.terminate()
        return simpleSpaceLifecycleResponse(
            for: .invalidRequest,
            capability: capability
        )
    }
    return await withAdmittedJSONWriteResponse(
        request.body,
        admission: capability.jsonWriteAdmission,
        policy: capability.jsonWriteBodyPolicy,
        maximumBytes: authenticatedSpaceWriteMaximumJSONBytes,
        termination: context.jsonWriteBodyTermination
    ) { data in
        do {
            try StrictPermissionedWriteJSON.validate(data)
            guard let root = try JSONSerialization.jsonObject(with: data)
                as? [String: Any],
                Set(root.keys).isSubset(of: allowed),
                required.isSubset(of: Set(root.keys)),
                !root.values.contains(where: { $0 is NSNull }) else {
                throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
            }
            try validateSimpleSpaceJSON(root)
            return try JSONDecoder().decode(type, from: data)
        } catch let failure as AuthenticatedSimpleSpaceLifecycleFailure {
            throw failure
        } catch {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
    } operation: { input in
        try await operation(input)
    } errorResponse: { error in
        simpleSpaceLifecycleResponse(for: error, capability: capability)
    }
}

func acceptsSimpleSpaceWriteContentLength(_ values: [String]) -> Bool {
    guard values.count <= 1 else { return false }
    guard let value = values.first else { return true }
    guard !value.isEmpty,
          value.utf8.allSatisfy({ (48...57).contains($0) }),
          value.first != "0",
          let length = Int(value) else {
        return false
    }
    return length <= authenticatedSpaceWriteMaximumJSONBytes
}

private func simpleSpaceLifecycleResponse(
    for error: any Error,
    capability: SwanAuthenticatedSimpleSpaceLifecycleCapability
) -> Response {
    if let failure = error as? AuthenticatedSimpleSpaceLifecycleFailure {
        return simpleSpaceLifecycleResponse(for: failure, capability: capability)
    }
    if let failure = error as? SwanJSONWriteBodyCollectionFailure {
        return simpleSpaceLifecycleResponse(for: failure)
    }
    return simpleSpaceLifecycleError(.badRequest, code: "InvalidRequest")
}

private func simpleSpaceLifecycleResponse(
    for failure: SwanJSONWriteBodyCollectionFailure
) -> Response {
    switch failure {
    case .invalidRequest:
        simpleSpaceLifecycleError(.badRequest, code: "InvalidRequest")
    case .unavailable:
        simpleSpaceLifecycleError(.serviceUnavailable, code: "temporarily_unavailable")
    }
}

/// Binds every field the six lifecycle contracts accept before the generated
/// decoder sees it. The duplicate-key parser above applies recursively; this
/// semantic pass rejects unknown/nullable nested configuration fields too.
private func validateSimpleSpaceJSON(_ root: [String: Any]) throws {
    for key in ["did", "type", "skey", "space", "policy", "managingApp"] {
        if let value = root[key] {
            guard let string = value as? String,
                  // The reference handler uses an empty `managingApp` on an
                  // update as an explicit clear sentinel. Every other string
                  // field is an identifier/policy and must remain nonempty.
                  (key == "managingApp" || !string.isEmpty),
                  string.utf8.count <= 2_048 else {
                throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
            }
        }
    }
    if let config = root["config"] {
        guard let object = config as? [String: Any] else {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
        try validateSimpleSpaceConfigJSON(object, requirePolicy: true)
    }
    if let appAccess = root["appAccess"] {
        guard let object = appAccess as? [String: Any] else {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
        try validateSimpleSpaceAppAccessJSON(object)
    }
}

private func validateSimpleSpaceConfigJSON(
    _ config: [String: Any],
    requirePolicy: Bool
) throws {
    let allowed: Set<String> = ["$type", "policy", "appAccess", "managingApp"]
    guard Set(config.keys).isSubset(of: allowed),
          (!requirePolicy || (config["policy"] is String && config["appAccess"] != nil)),
          !config.values.contains(where: { $0 is NSNull }) else {
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
    if let policy = config["policy"] {
        guard let policy = policy as? String,
              SimpleSpacePolicy(rawValue: policy) != nil else {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
    }
    if let managingApp = config["managingApp"] {
        guard let managingApp = managingApp as? String,
              !managingApp.isEmpty,
              managingApp.utf8.count <= 2_048 else {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
    }
    guard let appAccess = config["appAccess"] as? [String: Any] else {
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
    try validateSimpleSpaceAppAccessJSON(appAccess)
}

private func validateSimpleSpaceAppAccessJSON(_ access: [String: Any]) throws {
    guard let type = access["$type"] as? String else {
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
    switch type {
    case ComAtprotoSimplespaceDefs.Open.typeIdentifier:
        guard Set(access.keys) == Set(["$type"]) else {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
    case ComAtprotoSimplespaceDefs.AllowList.typeIdentifier:
        guard Set(access.keys) == Set(["$type", "allowed"]),
              let allowed = access["allowed"] as? [String],
              allowed.count <= 1_000,
              allowed.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 2_048 }) else {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
    default:
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
}

private func parseSimpleSpaceListMembersParameters(
    _ request: Request
) throws -> ComAtprotoSimplespaceListMembers.Parameters {
    guard !request.uri.string.contains("#"),
          let query = request.uri.query,
          !query.isEmpty,
          query.utf8.count <= 4_096 else {
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
    var values: [String: String] = [:]
    let allowed: Set<String> = ["space", "limit", "cursor"]
    for segment in query.split(separator: "&", omittingEmptySubsequences: false) {
        let pair = segment.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        guard pair.count == 2,
              !pair[0].isEmpty,
              pair[0].utf8.allSatisfy({ ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z")) || ($0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z")) }),
              allowed.contains(String(pair[0])),
              values[String(pair[0])] == nil else {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
        values[String(pair[0])] = try strictQueryDecode(pair[1])
    }
    guard let rawSpace = values["space"],
          rawSpace.utf8.count <= 2_048 else {
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
    let space = try ATProtocolURI(uriString: rawSpace)
    _ = try lifecycleSpace(space)
    let limit: Int?
    if let rawLimit = values["limit"] {
        guard rawLimit.utf8.allSatisfy({ $0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9") }),
              let value = Int(rawLimit),
              (1 ... 1_000).contains(value) else {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
        limit = value
    } else {
        limit = nil
    }
    let cursor: String?
    if let rawCursor = values["cursor"] {
        guard rawCursor.utf8.count <= 2_048 else {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
        _ = try DID(didString: rawCursor)
        cursor = rawCursor
    } else {
        cursor = nil
    }
    return .init(space: space, limit: limit, cursor: cursor)
}

private func registerSimpleSpaceWrongMethods(
    on router: Router<BasicRequestContext>,
    path: RouterPath,
    liveMethod: HTTPRequest.Method
) {
    let methods: [HTTPRequest.Method] = [.get, .head, .post, .put, .patch, .delete, .options, .connect, .trace]
    for method in methods where method != liveMethod {
        router.on(path, method: method) { _, _ -> Response in
            simpleSpaceLifecycleError(.notFound, code: "permissioned_endpoint_unavailable")
        }
    }
}

private func simpleSpaceLifecycleResponse(
    for failure: AuthenticatedSimpleSpaceLifecycleFailure,
    capability: SwanAuthenticatedSimpleSpaceLifecycleCapability
) -> Response {
    switch failure {
    case .invalidRequest:
        simpleSpaceLifecycleError(.badRequest, code: "InvalidRequest")
    case .spaceNotFound:
        simpleSpaceLifecycleError(.notFound, code: "SpaceNotFound")
    case .spaceAlreadyExists:
        simpleSpaceLifecycleError(.badRequest, code: "SpaceAlreadyExists")
    case .denied:
        simpleSpaceLifecycleError(.unauthorized, code: "Unauthorized")
    case .nonceChallenge:
        authenticatedGetSpaceNonceChallenge(authorizer: capability.authorizer)
    case .unavailable:
        simpleSpaceLifecycleError(.serviceUnavailable, code: "temporarily_unavailable")
    }
}

private func simpleSpaceLifecycleError(
    _ status: HTTPResponse.Status,
    code: String
) -> Response {
    authenticatedGetSpaceJSON(status, ["error": code])
}

private struct SimpleSpaceMembersWireOutput: Encodable {
    let cursor: String?
    let members: [SimpleSpaceMemberWireOutput]
}

private struct SimpleSpaceMemberWireOutput: Encodable {
    let did: String
}

private func simpleSpaceMembersJSON(
    _ status: HTTPResponse.Status,
    _ output: ComAtprotoSimplespaceListMembers.Output
) -> Response {
    authenticatedGetSpaceJSON(
        status,
        SimpleSpaceMembersWireOutput(
            cursor: output.cursor,
            members: output.members.map { .init(did: $0.did.didString()) }
        )
    )
}
