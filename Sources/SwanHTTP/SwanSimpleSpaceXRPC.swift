import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import Petrel
import SwanCore
import SwanOAuth
import SwanSpaces
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

enum AuthenticatedSimpleSpaceLifecycleFailure: Error {
    case invalidRequest
    case invalidCursor
    case invalidSpaceMeta
    case spaceNotFound
    case notAuthorized
    case spaceAlreadyExists
    case unsupportedPolicy
    case policyMismatch
    case denied
    case nonceChallenge
    case unavailable
}

/// `com.atproto.space.createSpace` input `{ spaceType, skey?, policy }`.
/// Swan's Petrel pin predates October 29, so the input is decoded by hand.
private struct SpaceCreateWireInput {
    let spaceType: String
    let skey: String?
    let policy: SpacePolicy

    init(_ root: SpaceLifecycleJSONObject) throws {
        spaceType = try lifecycleString(root["spaceType"])
        skey = try root["skey"].map(lifecycleString)
        policy = try lifecyclePolicy(root["policy"])
    }
}

/// `com.atproto.space.updateSpace` input `{ space, policy }`, both required.
private struct SpaceUpdateWireInput {
    let space: SpaceURI
    let policy: SpacePolicy

    init(_ root: SpaceLifecycleJSONObject) throws {
        space = try lifecycleSpace(root["space"])
        policy = try lifecyclePolicy(root["policy"])
    }
}

/// `{ space }`.
private struct SpaceWireInput {
    let space: SpaceURI

    init(_ root: SpaceLifecycleJSONObject) throws {
        space = try lifecycleSpace(root["space"])
    }
}

/// `com.atproto.space.removeWriter` input `{ space, repo }`.
private struct SpaceRemoveWriterWireInput {
    let space: SpaceURI
    let repo: String

    init(_ root: SpaceLifecycleJSONObject) throws {
        space = try lifecycleSpace(root["space"])
        repo = try lifecycleDID(root["repo"])
    }
}

/// `com.atproto.memberspace.putMembers` input.
private struct SpacePutMembersWireInput {
    let space: SpaceURI
    let members: [AuthorizedSimpleSpaceMemberPage.Member]

    init(_ root: SpaceLifecycleJSONObject) throws {
        space = try lifecycleSpace(root["space"])
        guard let values = root["members"] as? [Any], values.count <= 100 else {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
        members = try values.map { value in
            guard let member = value as? [String: Any],
                  member["did"] != nil, member["read"] != nil, member["write"] != nil else {
                throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
            }
            if let type = member["$type"],
               type as? String != "com.atproto.memberspace.defs#member" {
                throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
            }
            return AuthorizedSimpleSpaceMemberPage.Member(
                did: try lifecycleDID(member["did"]),
                read: try lifecycleBool(member["read"]),
                write: try lifecycleBool(member["write"])
            )
        }
    }
}

/// `com.atproto.memberspace.removeMembers` input.
private struct SpaceRemoveMembersWireInput {
    let space: SpaceURI
    let dids: [String]

    init(_ root: SpaceLifecycleJSONObject) throws {
        space = try lifecycleSpace(root["space"])
        guard let values = root["dids"] as? [Any], values.count <= 100 else {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
        dids = try values.map(lifecycleDID)
    }
}

private func lifecycleString(_ value: Any?) throws -> String {
    guard let string = value as? String, !string.isEmpty, string.utf8.count <= 2_048 else {
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
    return string
}

private func lifecycleBool(_ value: Any?) throws -> Bool {
    guard let value, SpacePolicy.isJSONBoolean(value), let bool = value as? Bool else {
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
    return bool
}

private func lifecycleDID(_ value: Any?) throws -> String {
    let string = try lifecycleString(value)
    do {
        return try DID(didString: string).didString()
    } catch {
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
}

func lifecycleSpace(_ value: Any?) throws -> SpaceURI {
    let string = try lifecycleString(value)
    do {
        return try SpaceURI(SpaceRef(uriString: string).uriString())
    } catch {
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
}

private func lifecyclePolicy(_ value: Any?) throws -> SpacePolicy {
    guard let value else { throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest }
    do {
        return try SpacePolicy.normalized(jsonObject: value)
    } catch SpacePolicyError.unsupportedPolicy {
        throw AuthenticatedSimpleSpaceLifecycleFailure.unsupportedPolicy
    } catch {
        throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
    }
}

private struct AuthenticatedSpaceCreateHandler {
    let capability: SwanAuthenticatedSimpleSpaceLifecycleCapability

    func handle(_ input: SpaceCreateWireInput, request: Request) async throws -> SpaceCreateWireOutput {
        // Authorization runs before the space URI is built: the authority is
        // the caller, so identity must be known first.
        let authorization = try await lifecycleAuthorization(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/com.atproto.space.createSpace"
        )
        guard case let .accountOAuth(subject, _) = authorization else {
            throw AuthenticatedSimpleSpaceLifecycleFailure.spaceNotFound
        }
        let space: SpaceURI
        do {
            let skey: String
            if let supplied = input.skey {
                skey = supplied
            } else {
                skey = try await capability.tidAllocator.next().toString()
            }
            space = try SpaceURI(
                authority: subject,
                spaceType: try NSID(nsidString: input.spaceType).nsidString(),
                skey: skey
            )
        } catch {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
        }
        try requireLifecycleAuthority(authorization, space: space)
        do {
            try await capability.directory.createSimpleSpace(
                space,
                configuration: SimpleSpaceConfiguration(policy: input.policy),
                authorization: authorization
            )
        } catch {
            throw lifecycleFailure(for: error)
        }
        return SpaceCreateWireOutput(space: space.rawValue)
    }
}

private struct SpaceCreateWireOutput: Encodable {
    let space: String
}

private struct AuthenticatedSpaceUpdateHandler {
    let capability: SwanAuthenticatedSimpleSpaceLifecycleCapability

    func handle(_ input: SpaceUpdateWireInput, request: Request) async throws {
        let authorization = try await lifecycleAuthorization(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/com.atproto.space.updateSpace"
        )
        try requireLifecycleAuthority(authorization, space: input.space)
        do {
            try await capability.directory.updateSimpleSpace(
                input.space,
                configuration: SimpleSpaceConfiguration(policy: input.policy),
                authorization: authorization
            )
        } catch {
            throw lifecycleFailure(for: error)
        }
    }
}

private func recordLocalSpaceCredentialRevocations(
    _ capability: SwanAuthenticatedSimpleSpaceLifecycleCapability,
    space: SpaceURI
) async {
    guard let credentialIDs = try? await capability.directory.recentlyRevokedSpaceCredentialIDs(space),
          !credentialIDs.isEmpty else {
        return
    }
    let chunkSize = DurableSpaceCredentialRevocations.maximumCredentialsPerNotification
    var start = 0
    while start < credentialIDs.count {
        let end = min(start + chunkSize, credentialIDs.count)
        try? await capability.authorizer.recordSpaceCredentialRevocations(
            space: space,
            credentialIDs: Array(credentialIDs[start ..< end])
        )
        start = end
    }
}

private struct AuthenticatedSpaceDeleteHandler {
    let capability: SwanAuthenticatedSimpleSpaceLifecycleCapability

    func handle(_ input: SpaceWireInput, request: Request) async throws {
        let authorization = try await lifecycleAuthorization(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/com.atproto.space.deleteSpace"
        )
        try requireLifecycleAuthority(authorization, space: input.space)
        do {
            try await capability.directory.deleteSimpleSpace(input.space, authorization: authorization)
        } catch {
            throw lifecycleFailure(for: error)
        }
        await recordLocalSpaceCredentialRevocations(capability, space: input.space)
    }
}

private struct AuthenticatedSpaceRemoveWriterHandler {
    let capability: SwanAuthenticatedSimpleSpaceLifecycleCapability

    func handle(_ input: SpaceRemoveWriterWireInput, request: Request) async throws {
        let authorization = try await lifecycleAuthorization(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/com.atproto.space.removeWriter"
        )
        try requireLifecycleAuthority(authorization, space: input.space)
        do {
            try await capability.directory.removeSpaceWriter(
                input.repo,
                from: input.space,
                authorization: authorization
            )
        } catch {
            throw lifecycleFailure(for: error)
        }
    }
}

private struct AuthenticatedMemberspacePutMembersHandler {
    let capability: SwanAuthenticatedSimpleSpaceLifecycleCapability

    func handle(_ input: SpacePutMembersWireInput, request: Request) async throws {
        let authorization = try await lifecycleAuthorization(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/\(ComAtprotoMemberspacePutMembers.typeIdentifier)"
        )
        try requireLifecycleAuthority(authorization, space: input.space)
        do {
            try await capability.directory.putSimpleSpaceMembers(
                input.members,
                in: input.space,
                authorization: authorization
            )
        } catch {
            throw lifecycleFailure(for: error)
        }
    }
}

private struct AuthenticatedMemberspaceRemoveMembersHandler {
    let capability: SwanAuthenticatedSimpleSpaceLifecycleCapability

    func handle(_ input: SpaceRemoveMembersWireInput, request: Request) async throws {
        let authorization = try await lifecycleAuthorization(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/\(ComAtprotoMemberspaceRemoveMembers.typeIdentifier)"
        )
        try requireLifecycleAuthority(authorization, space: input.space)
        do {
            try await capability.directory.removeSimpleSpaceMembers(
                input.dids,
                from: input.space,
                authorization: authorization
            )
        } catch {
            throw lifecycleFailure(for: error)
        }
        await recordLocalSpaceCredentialRevocations(capability, space: input.space)
    }
}

private struct MemberspaceListMembersParameters {
    let space: SpaceURI
    let limit: Int?
    let cursor: String?
}

private struct AuthenticatedMemberspaceListMembersHandler {
    let capability: SwanAuthenticatedSimpleSpaceLifecycleCapability

    func handle(
        _ parameters: MemberspaceListMembersParameters,
        request: Request
    ) async throws -> SimpleSpaceMembersWireOutput {
        let space = parameters.space
        let authorization = try await lifecycleAuthorization(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/com.atproto.memberspace.listMembers",
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
        return SimpleSpaceMembersWireOutput(
            cursor: page.cursor,
            members: page.members.map { .init(did: $0.did, read: $0.read, write: $0.write) }
        )
    }
}

func registerAuthenticatedSimpleSpaceLifecycleEndpoints(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSimpleSpaceLifecycleCapability
) {
    let create = AuthenticatedSpaceCreateHandler(capability: capability)
    registerSpaceLifecycleProcedure(
        on: router, path: "/xrpc/com.atproto.space.createSpace", capability: capability,
        required: ["spaceType", "policy"], allowed: ["spaceType", "skey", "policy"]
    ) { root, request in
        authenticatedGetSpaceJSON(.ok, try await create.handle(try SpaceCreateWireInput(root), request: request))
    }
    let update = AuthenticatedSpaceUpdateHandler(capability: capability)
    registerSpaceLifecycleProcedure(
        on: router, path: "/xrpc/com.atproto.space.updateSpace", capability: capability,
        required: ["space", "policy"], allowed: ["space", "policy"]
    ) { root, request in
        try await update.handle(try SpaceUpdateWireInput(root), request: request)
        return Response(status: .ok, headers: [.cacheControl: "no-store"])
    }
    let delete = AuthenticatedSpaceDeleteHandler(capability: capability)
    registerSpaceLifecycleProcedure(
        on: router, path: "/xrpc/com.atproto.space.deleteSpace", capability: capability,
        required: ["space"], allowed: ["space"]
    ) { root, request in
        try await delete.handle(try SpaceWireInput(root), request: request)
        return Response(status: .ok, headers: [.cacheControl: "no-store"])
    }
    let removeWriter = AuthenticatedSpaceRemoveWriterHandler(capability: capability)
    registerSpaceLifecycleProcedure(
        on: router, path: "/xrpc/com.atproto.space.removeWriter", capability: capability,
        required: ["space", "repo"], allowed: ["space", "repo"]
    ) { root, request in
        try await removeWriter.handle(try SpaceRemoveWriterWireInput(root), request: request)
        return Response(status: .ok, headers: [.cacheControl: "no-store"])
    }
    let putMembers = AuthenticatedMemberspacePutMembersHandler(capability: capability)
    registerSpaceLifecycleProcedure(
        on: router, path: RouterPath("/xrpc/\(ComAtprotoMemberspacePutMembers.typeIdentifier)"), capability: capability,
        required: ["space", "members"], allowed: ["space", "members"]
    ) { root, request in
        try await putMembers.handle(try SpacePutMembersWireInput(root), request: request)
        return Response(status: .ok, headers: [.cacheControl: "no-store"])
    }
    let removeMembers = AuthenticatedMemberspaceRemoveMembersHandler(capability: capability)
    registerSpaceLifecycleProcedure(
        on: router, path: RouterPath("/xrpc/\(ComAtprotoMemberspaceRemoveMembers.typeIdentifier)"), capability: capability,
        required: ["space", "dids"], allowed: ["space", "dids"]
    ) { root, request in
        try await removeMembers.handle(try SpaceRemoveMembersWireInput(root), request: request)
        return Response(status: .ok, headers: [.cacheControl: "no-store"])
    }
    registerMemberspaceListMembers(on: router, capability: capability)
    registerAuthenticatedSpaceMetaEndpoints(on: router, capability: capability)
}

private func registerSpaceLifecycleProcedure(
    on router: Router<BasicRequestContext>,
    path: RouterPath,
    capability: SwanAuthenticatedSimpleSpaceLifecycleCapability,
    required: Set<String>,
    allowed: Set<String>,
    operation: @escaping @Sendable (SpaceLifecycleJSONObject, Request) async throws -> Response
) {
    router.post(path) { request, context async -> Response in
        await withSimpleSpaceInput(
            request,
            context: context,
            capability: capability,
            required: required,
            allowed: allowed
        ) { root in
            try await operation(root, request)
        }
    }
    registerSimpleSpaceWrongMethods(on: router, path: path, liveMethod: .post)
}

/// A strictly validated JSON object body. `[String: Any]` is not `Sendable`;
/// the dictionary is created and consumed within one request task.
struct SpaceLifecycleJSONObject: @unchecked Sendable {
    let root: [String: Any]
    subscript(key: String) -> Any? { root[key] }
}

private func registerMemberspaceListMembers(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSimpleSpaceLifecycleCapability
) {
    let handler = AuthenticatedMemberspaceListMembersHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.memberspace.listMembers"
    router.get(path) { request, _ async -> Response in
        do {
            let parameters = try parseSimpleSpaceListMembersParameters(request)
            let output = try await handler.handle(parameters, request: request)
            return authenticatedGetSpaceJSON(.ok, output)
        } catch let failure as AuthenticatedSimpleSpaceLifecycleFailure {
            return simpleSpaceLifecycleResponse(for: failure, capability: capability)
        } catch {
            return simpleSpaceLifecycleError(.badRequest, code: "InvalidRequest")
        }
    }
    registerSimpleSpaceWrongMethods(on: router, path: path, liveMethod: .get)
}

func lifecycleAuthorization(
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

func lifecycleFailure(for error: Error) -> AuthenticatedSimpleSpaceLifecycleFailure {
    if error is AuthorizedSimpleSpaceLifecycleError {
        return .spaceNotFound
    }
    if let error = error as? SpacePolicyError {
        switch error {
        case .unsupportedPolicy: return .unsupportedPolicy
        case .invalidPolicy: return .invalidRequest
        case .policyMismatch: return .policyMismatch
        }
    }
    guard let error = error as? SwanError else { return .unavailable }
    switch error {
    case .conflict: return .spaceAlreadyExists
    case .unauthorized, .expired: return .notAuthorized
    case .invalidIdentifier, .malformed: return .invalidRequest
    case .invalidProfile, .unavailable: return .unavailable
    }
}

private func withSimpleSpaceInput(
    _ request: Request,
    context: SwanHTTPRequestContext,
    capability: SwanAuthenticatedSimpleSpaceLifecycleCapability,
    required: Set<String>,
    allowed: Set<String>,
    operation: (SpaceLifecycleJSONObject) async throws -> Response
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
                // Key names only — never field values, which may hold DIDs
                // or space configuration the caller expects to stay private.
                if let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    context.logger.info(
                        "simplespace write rejected",
                        metadata: [
                            "stage": .string("key_set"),
                            "received": .string(root.keys.sorted().joined(separator: ",")),
                            "required": .string(required.sorted().joined(separator: ",")),
                            "allowed": .string(allowed.sorted().joined(separator: ",")),
                        ])
                }
                throw AuthenticatedSimpleSpaceLifecycleFailure.invalidRequest
            }
            return SpaceLifecycleJSONObject(root: root)
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

func simpleSpaceLifecycleResponse(
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

func simpleSpaceLifecycleResponse(
    for failure: SwanJSONWriteBodyCollectionFailure
) -> Response {
    switch failure {
    case .invalidRequest:
        simpleSpaceLifecycleError(.badRequest, code: "InvalidRequest")
    case .unavailable:
        simpleSpaceLifecycleError(.serviceUnavailable, code: "temporarily_unavailable")
    }
}

private func parseSimpleSpaceListMembersParameters(
    _ request: Request
) throws -> MemberspaceListMembersParameters {
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
    let space = try lifecycleSpace(rawSpace)
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
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidCursor
        }
        do {
            _ = try DID(didString: rawCursor)
        } catch {
            throw AuthenticatedSimpleSpaceLifecycleFailure.invalidCursor
        }
        cursor = rawCursor
    } else {
        cursor = nil
    }
    return MemberspaceListMembersParameters(space: space, limit: limit, cursor: cursor)
}

func registerSimpleSpaceWrongMethods(
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

func simpleSpaceLifecycleResponse(
    for failure: AuthenticatedSimpleSpaceLifecycleFailure,
    capability: SwanAuthenticatedSimpleSpaceLifecycleCapability
) -> Response {
    switch failure {
    case .invalidRequest:
        simpleSpaceLifecycleError(.badRequest, code: "InvalidRequest")
    case .invalidCursor:
        simpleSpaceLifecycleError(.badRequest, code: "InvalidCursor")
    case .invalidSpaceMeta:
        simpleSpaceLifecycleError(.badRequest, code: "InvalidSpaceMeta")
    case .spaceNotFound:
        simpleSpaceLifecycleError(.badRequest, code: "SpaceNotFound")
    case .notAuthorized:
        simpleSpaceLifecycleError(.badRequest, code: "NotAuthorized")
    case .spaceAlreadyExists:
        simpleSpaceLifecycleError(.badRequest, code: "SpaceAlreadyExists")
    case .unsupportedPolicy:
        simpleSpaceLifecycleError(.badRequest, code: "UnsupportedPolicy")
    case .policyMismatch:
        simpleSpaceLifecycleError(.badRequest, code: "PolicyMismatch")
    case .denied:
        simpleSpaceLifecycleError(.unauthorized, code: "Unauthorized")
    case .nonceChallenge:
        authenticatedGetSpaceNonceChallenge(authorizer: capability.authorizer)
    case .unavailable:
        simpleSpaceLifecycleError(.serviceUnavailable, code: "temporarily_unavailable")
    }
}

func simpleSpaceLifecycleError(
    _ status: HTTPResponse.Status,
    code: String
) -> Response {
    authenticatedGetSpaceJSON(status, ["error": code])
}

struct SimpleSpaceMembersWireOutput: Encodable {
    let cursor: String?
    let members: [SimpleSpaceMemberWireOutput]
}

struct SimpleSpaceMemberWireOutput: Encodable {
    let did: String
    let read: Bool
    let write: Bool
}
