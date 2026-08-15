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

/// The internal capability required to expose the authenticated authority
/// description endpoint. A ``SwanHTTPServer`` creates it itself from its
/// canonical public URL and OAuth runtime, so an authorizer for a different
/// htu or token runtime can never be accidentally attached to this route.
public struct SwanAuthenticatedGetSpaceCapability: Sendable {
    let authorizer: SwanOAuthResourceAuthorizer
    let directory: any AuthorizedSimpleSpaceDirectory

    init(
        authorizer: SwanOAuthResourceAuthorizer,
        directory: any AuthorizedSimpleSpaceDirectory
    ) {
        self.authorizer = authorizer
        self.directory = directory
    }
}

private enum AuthenticatedGetSpaceFailure: Error {
    case invalidRequest
    case spaceNotFound
    case denied
    case nonceChallenge
    case unavailable
}

/// The handler conforms to the checked-in lexicon server contract. The HTTP
/// adapter owns the strict query parse and response/error mapping; the
/// contract handler owns the typed authorization and output translation.
private struct AuthenticatedGetSpaceHandler: ComAtprotoSpaceGetSpace.ServerHandler {
    typealias Context = Request

    let capability: SwanAuthenticatedGetSpaceCapability

    func handle(
        parameters: ComAtprotoSpaceGetSpace.Parameters,
        input: Void,
        context request: Request
    ) async throws -> ComAtprotoSpaceGetSpace.Output {
        let space: SpaceURI
        do {
            // Parse both representations deliberately. `ATProtocolURI` is
            // the generated XRPC input type, while the domain type enforces
            // Swan's exact three-part permissioned-space URI shape.
            space = try SpaceURI(parameters.space.uriString())
        } catch {
            throw AuthenticatedGetSpaceFailure.invalidRequest
        }

        let authorization: AuthorizationContext
        do {
            authorization = try await capability.authorizer.authorize(
                request: request,
                method: "GET",
                fixedPath: "/xrpc/com.atproto.space.getSpace"
            )
        } catch let failure as SwanResourceAuthorizationFailure {
            throw switch failure {
            case .nonceChallengeRequired: AuthenticatedGetSpaceFailure.nonceChallenge
            case .denied: AuthenticatedGetSpaceFailure.denied
            case .unavailable: AuthenticatedGetSpaceFailure.unavailable
            }
        } catch {
            throw AuthenticatedGetSpaceFailure.unavailable
        }

        guard case let .accountOAuth(subject, _) = authorization else {
            throw AuthenticatedGetSpaceFailure.denied
        }
        // A valid account token for another authority must not prove whether
        // this space exists. The wire endpoint uses its declared not-found
        // result for that deliberately opaque authority mismatch.
        guard subject == space.authority else {
            throw AuthenticatedGetSpaceFailure.spaceNotFound
        }

        let description: AuthenticatedSimpleSpaceDescription?
        do {
            description = try await capability.directory.space(
                space,
                authorization: authorization
            )
        } catch let error as SwanError {
            if case .unauthorized = error {
                // This is a directory/authority policy failure, distinct
                // from a nonexistent resource. Do not render details.
                throw AuthenticatedGetSpaceFailure.denied
            }
            throw AuthenticatedGetSpaceFailure.unavailable
        } catch {
            throw AuthenticatedGetSpaceFailure.unavailable
        }
        guard let description else {
            throw AuthenticatedGetSpaceFailure.spaceNotFound
        }
        // This is redundant for SwanSQLite but mandatory at this module
        // boundary: the protocol deliberately permits alternative storage
        // adapters. Never serialize a description for a different authority
        // or space key just because an adapter returned one.
        guard description.space == space else {
            throw AuthenticatedGetSpaceFailure.unavailable
        }

        do {
            return try output(for: description)
        } catch {
            // A startup-preopened directory is expected to validate its
            // durable state. Treat an impossible projection failure as an
            // availability failure, never as a partly-rendered response.
            throw AuthenticatedGetSpaceFailure.unavailable
        }
    }

    private func output(
        for description: AuthenticatedSimpleSpaceDescription
    ) throws -> ComAtprotoSpaceGetSpace.Output {
        let appAccess: ComAtprotoSimplespaceDefs.SpaceConfigAppAccessUnion
        switch description.configuration.appAccess {
        case .open:
            appAccess = .comAtprotoSimplespaceDefsOpen(.init())
        case let .allowList(allowed):
            // Client IDs are an intentional part of the wire SpaceConfig.
            // They become visible only after the authority DPoP check above.
            appAccess = .comAtprotoSimplespaceDefsAllowList(.init(allowed: allowed.sorted()))
        }
        let config = ComAtprotoSimplespaceDefs.SpaceConfig(
            policy: description.configuration.policy.rawValue,
            appAccess: appAccess,
            managingApp: description.configuration.managingApp
        )
        return ComAtprotoSpaceGetSpace.Output(
            uri: try ATProtocolURI(uriString: description.space.rawValue),
            config: .comAtprotoSimplespaceDefsSpaceConfig(config)
        )
    }
}

func registerAuthenticatedGetSpaceEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedGetSpaceCapability
) {
    let handler = AuthenticatedGetSpaceHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.getSpace"
    router.get(path) { request, _ async -> Response in
        let parameters: ComAtprotoSpaceGetSpace.Parameters
        do {
            parameters = try parseAuthenticatedGetSpaceParameters(request)
        } catch {
            return authenticatedGetSpaceError(.badRequest, code: "InvalidRequest")
        }

        do {
            let output = try await handler.handle(parameters: parameters, input: (), context: request)
            return authenticatedGetSpaceJSON(.ok, output)
        } catch let failure as AuthenticatedGetSpaceFailure {
            return authenticatedGetSpaceResponse(for: failure, capability: capability)
        } catch {
            return authenticatedGetSpaceError(.serviceUnavailable, code: "temporarily_unavailable")
        }
    }

    // Once this opt-in endpoint is live, keep every non-GET invocation in
    // the same explicit, no-store XRPC closure. This is deliberately scoped
    // to this route; all other profile methods retain their generic gates.
    for method: HTTPRequest.Method in [.head, .post, .put, .patch, .delete, .options, .connect, .trace] {
        router.on(path, method: method) { _, _ -> Response in
            authenticatedGetSpaceError(.notFound, code: "permissioned_endpoint_unavailable")
        }
    }
}

private func authenticatedGetSpaceResponse(
    for failure: AuthenticatedGetSpaceFailure,
    capability: SwanAuthenticatedGetSpaceCapability
) -> Response {
    switch failure {
    case .invalidRequest:
        authenticatedGetSpaceError(.badRequest, code: "InvalidRequest")
    case .spaceNotFound:
        authenticatedGetSpaceError(.notFound, code: "SpaceNotFound")
    case .denied:
        authenticatedGetSpaceError(.unauthorized, code: "Unauthorized")
    case .nonceChallenge:
        authenticatedGetSpaceNonceChallenge(authorizer: capability.authorizer)
    case .unavailable:
        authenticatedGetSpaceError(.serviceUnavailable, code: "temporarily_unavailable")
    }
}

private func parseAuthenticatedGetSpaceParameters(
    _ request: Request
) throws -> ComAtprotoSpaceGetSpace.Parameters {
    // `URI.query` intentionally strips a fragment, so retain the original
    // request target as a separate guard. A fragment must never alter the
    // identifier used for authorization or directory lookup.
    guard !request.uri.string.contains("#"),
          let query = request.uri.query,
          !query.isEmpty,
          query.utf8.count <= 4_096,
          !query.contains("&"),
          let separator = query.firstIndex(of: "=") else {
        throw AuthenticatedGetSpaceFailure.invalidRequest
    }
    let key = query[..<separator]
    let encodedValue = query[query.index(after: separator)...]
    guard key == "space", !encodedValue.isEmpty else {
        throw AuthenticatedGetSpaceFailure.invalidRequest
    }
    let rawSpace = try strictQueryDecode(encodedValue)
    let uri: ATProtocolURI
    do {
        uri = try ATProtocolURI(uriString: rawSpace)
        _ = try SpaceURI(uri.uriString())
    } catch {
        throw AuthenticatedGetSpaceFailure.invalidRequest
    }
    return .init(space: uri)
}

func strictQueryDecode(_ encoded: Substring) throws -> String {
    var decoded = [UInt8]()
    decoded.reserveCapacity(encoded.utf8.count)
    var iterator = encoded.utf8.makeIterator()
    while let byte = iterator.next() {
        switch byte {
        case UInt8(ascii: "%"):
            guard let high = iterator.next(), let low = iterator.next(),
                  let highNibble = hexNibble(high), let lowNibble = hexNibble(low) else {
                throw AuthenticatedGetSpaceFailure.invalidRequest
            }
            decoded.append(highNibble << 4 | lowNibble)
        case 0 ... 31, 127:
            throw AuthenticatedGetSpaceFailure.invalidRequest
        default:
            decoded.append(byte)
        }
    }
    guard let value = String(bytes: decoded, encoding: .utf8),
          !value.isEmpty,
          !value.unicodeScalars.contains(where: { scalar in
              scalar.properties.generalCategory == .control
          }) else {
        throw AuthenticatedGetSpaceFailure.invalidRequest
    }
    return value
}

private func hexNibble(_ byte: UInt8) -> UInt8? {
    switch byte {
    case UInt8(ascii: "0") ... UInt8(ascii: "9"): byte - UInt8(ascii: "0")
    case UInt8(ascii: "A") ... UInt8(ascii: "F"): byte - UInt8(ascii: "A") + 10
    case UInt8(ascii: "a") ... UInt8(ascii: "f"): byte - UInt8(ascii: "a") + 10
    default: nil
    }
}

func authenticatedGetSpaceNonceChallenge(
    authorizer: SwanOAuthResourceAuthorizer
) -> Response {
    var headers = HTTPFields()
    headers[.contentType] = "application/json"
    headers[.cacheControl] = "no-store"
    headers[HTTPField.Name("DPoP-Nonce")!] = authorizer.issueNonce()
    headers[.wwwAuthenticate] = "DPoP error=\"use_dpop_nonce\""
    let data = (try? JSONEncoder().encode(["error": "use_dpop_nonce"])) ?? Data("{}".utf8)
    return Response(
        status: .unauthorized,
        headers: headers,
        body: .init(byteBuffer: ByteBuffer(data: data))
    )
}

private func authenticatedGetSpaceError(
    _ status: HTTPResponse.Status,
    code: String
) -> Response {
    authenticatedGetSpaceJSON(status, ["error": code])
}

func authenticatedGetSpaceJSON(
    _ status: HTTPResponse.Status,
    _ body: some Encodable,
    maximumBytes: Int = PublicRepositoryJSONReadLimits
        .maximumListRecordsResponseBytes,
    lease: PublicRepositoryJSONReadLease? = nil
) -> Response {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    guard maximumBytes > 0 else {
        lease?.release()
        return authenticatedGetSpaceError(.serviceUnavailable, code: "temporarily_unavailable")
    }
    let data = (try? encoder.encode(body)) ?? Data("{}".utf8)
    guard data.count <= maximumBytes else {
        lease?.release()
        return authenticatedGetSpaceError(.serviceUnavailable, code: "temporarily_unavailable")
    }
    if let lease {
        return Response(
            status: status,
            headers: [.contentType: "application/json", .cacheControl: "no-store"],
            body: .init(contentLength: data.count) { writer in
                defer { lease.release() }
                try await writer.write(ByteBuffer(data: data))
                try await writer.finish(nil)
            }
        )
    }
    return Response(
        status: status,
        headers: [.contentType: "application/json", .cacheControl: "no-store"],
        body: .init(byteBuffer: ByteBuffer(data: data))
    )
}

// MARK: - Authenticated permissioned record reads

/// The internal capability required to expose the first permissioned record
/// reads. It is formed only by ``SwanHTTPServer`` after binding one durable
/// OAuth runtime to its configured public URL and confirming that the supplied
/// startup directory exposes the intentionally narrow repository projection.
public struct SwanAuthenticatedSpaceRecordsCapability: Sendable {
    let authorizer: SwanOAuthResourceAuthorizer
    let directory: any AuthorizedSpaceRepositoryDirectory
    /// Nil means only the established OAuth/DPoP route is enabled. A present
    /// verifier is invoked only for an exact `Authorization: Bearer` space
    /// credential; it never sees DPoP access tokens.
    let credentialAuthorizer: (any SpaceCredentialAuthorizationVerifier)?
    let tidAllocator: SwanPermissionedTIDAllocator
    /// Shared with anonymous public JSON reads so authenticated permissioned
    /// pages cannot multiply the same allocation-heavy response buffers.
    let jsonReadAdmission: PublicRepositoryJSONReadAdmission
    let jsonWriteAdmission: PublicRepositoryJSONWriteAdmission
    let jsonWriteBodyPolicy: SwanJSONWriteBodyPolicy

    init(
        authorizer: SwanOAuthResourceAuthorizer,
        directory: any AuthorizedSpaceRepositoryDirectory,
        credentialAuthorizer: (any SpaceCredentialAuthorizationVerifier)? = nil,
        jsonReadAdmission: PublicRepositoryJSONReadAdmission = .processShared,
        jsonWriteAdmission: PublicRepositoryJSONWriteAdmission = .processShared,
        jsonWriteBodyPolicy: SwanJSONWriteBodyPolicy = .productionDefault
    ) {
        self.authorizer = authorizer
        self.directory = directory
        self.credentialAuthorizer = credentialAuthorizer
        tidAllocator = SwanPermissionedTIDAllocator()
        self.jsonReadAdmission = jsonReadAdmission
        self.jsonWriteAdmission = jsonWriteAdmission
        self.jsonWriteBodyPolicy = jsonWriteBodyPolicy
    }
}

private enum AuthenticatedSpaceRecordFailure: Error {
    case invalidRequest
    case spaceNotFound
    case recordNotFound
    case denied
    case nonceChallenge
    case unavailable
}

private struct AuthenticatedGetRecordHandler: ComAtprotoSpaceGetRecord.ServerHandler {
    typealias Context = Request

    let capability: SwanAuthenticatedSpaceRecordsCapability

    func handle(
        parameters: ComAtprotoSpaceGetRecord.Parameters,
        input: Void,
        context request: Request
    ) async throws -> ComAtprotoSpaceGetRecord.Output {
        let uri: SpaceRecordURI
        do {
            let space = try SpaceURI(parameters.space.uriString())
            uri = try SpaceRecordURI(
                space: space,
                author: parameters.repo.didString(),
                collection: parameters.collection.nsidString(),
                rkey: parameters.rkey.value
            )
        } catch {
            throw AuthenticatedSpaceRecordFailure.invalidRequest
        }

        let authorization = try await authorizeRecordRead(
            capability,
            request: request,
            expectedSpace: uri.space,
            fixedPath: "/xrpc/com.atproto.space.getRecord"
        )
        switch authorization {
        case let .accountOAuth(subject, _) where subject == uri.author:
            break
        case .spaceCredential:
            break
        default:
            // A valid OAuth principal for another repository must not prove
            // whether this space or record exists. A verified credential is
            // intentionally different: it is the proposal's cross-member
            // read grant and its exact space was already bound above.
            throw AuthenticatedSpaceRecordFailure.spaceNotFound
        }

        let record: SpaceRecord?
        do {
            record = try await capability.directory.record(
                uri,
                authorization: authorization
            )
        } catch let error as SwanError {
            if case .unauthorized = error {
                throw AuthenticatedSpaceRecordFailure.denied
            }
            throw AuthenticatedSpaceRecordFailure.unavailable
        } catch {
            throw AuthenticatedSpaceRecordFailure.unavailable
        }
        guard let record else {
            throw AuthenticatedSpaceRecordFailure.recordNotFound
        }
        guard record.uri == uri else {
            throw AuthenticatedSpaceRecordFailure.unavailable
        }

        do {
            let cid = try CID.parse(record.cid)
            guard CID.fromDAGCBOR(record.value) == cid else {
                throw AuthenticatedSpaceRecordFailure.unavailable
            }
            return ComAtprotoSpaceGetRecord.Output(
                uri: try ATProtocolURI(uriString: record.uri.rawValue),
                cid: cid,
                value: try CARRepository.decodeRecordCBOR(record.value)
            )
        } catch let failure as AuthenticatedSpaceRecordFailure {
            throw failure
        } catch {
            // A persistence corruption is never converted into a JSON
            // approximation of a permissioned record.
            throw AuthenticatedSpaceRecordFailure.unavailable
        }
    }
}

private struct AuthenticatedListRecordsHandler: ComAtprotoSpaceListRecords.ServerHandler {
    typealias Context = Request

    let capability: SwanAuthenticatedSpaceRecordsCapability

    func handle(
        parameters: ComAtprotoSpaceListRecords.Parameters,
        input: Void,
        context request: Request
    ) async throws -> ComAtprotoSpaceListRecords.Output {
        let space: SpaceURI
        let repo: String
        let collection: String?
        do {
            space = try SpaceURI(parameters.space.uriString())
            repo = parameters.repo.didString()
            collection = parameters.collection?.nsidString()
            // Domain construction performs the stricter Swan identifier
            // validation, even when the request lists across collections.
            _ = try SpaceRecordURI(
                space: space,
                author: repo,
                collection: collection ?? "app.swan.records",
                rkey: "scope"
            )
        } catch {
            throw AuthenticatedSpaceRecordFailure.invalidRequest
        }

        let authorization = try await authorizeRecordRead(
            capability,
            request: request,
            expectedSpace: space,
            fixedPath: "/xrpc/com.atproto.space.listRecords"
        )
        switch authorization {
        case let .accountOAuth(subject, _) where subject == repo:
            break
        case .spaceCredential:
            break
        default:
            throw AuthenticatedSpaceRecordFailure.spaceNotFound
        }

        let records: [SpaceRecord]
        do {
            records = try await capability.directory.records(
                space: space,
                author: repo,
                collection: collection,
                limit: parameters.limit ?? 50,
                cursor: parameters.cursor,
                reverse: parameters.reverse ?? false,
                authorization: authorization
            )
        } catch let error as SwanError {
            if case .unauthorized = error {
                throw AuthenticatedSpaceRecordFailure.denied
            }
            throw AuthenticatedSpaceRecordFailure.unavailable
        } catch {
            throw AuthenticatedSpaceRecordFailure.unavailable
        }

        do {
            let outputRecords = try records.map { record in
                guard record.uri.space == space, record.uri.author == repo else {
                    throw AuthenticatedSpaceRecordFailure.unavailable
                }
                let cid = try CID.parse(record.cid)
                guard CID.fromDAGCBOR(record.value) == cid else {
                    throw AuthenticatedSpaceRecordFailure.unavailable
                }
                let value = parameters.excludeValues == true
                    ? nil
                    : try CARRepository.decodeRecordCBOR(record.value)
                return ComAtprotoSpaceListRecords.Record(
                    collection: try NSID(nsidString: record.uri.collection),
                    rkey: try RecordKey(keyString: record.uri.rkey),
                    cid: cid,
                    value: value
                )
            }
            let cursor = outputRecords.last.map {
                "\($0.collection.nsidString())/\($0.rkey.value)"
            }
            return ComAtprotoSpaceListRecords.Output(
                cursor: cursor,
                records: outputRecords
            )
        } catch let failure as AuthenticatedSpaceRecordFailure {
            throw failure
        } catch {
            throw AuthenticatedSpaceRecordFailure.unavailable
        }
    }
}

func registerAuthenticatedGetRecordEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceRecordsCapability
) {
    let handler = AuthenticatedGetRecordHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.getRecord"
    router.get(path) { request, _ async -> Response in
        let parameters: ComAtprotoSpaceGetRecord.Parameters
        do {
            parameters = try parseAuthenticatedGetRecordParameters(request)
        } catch {
            return authenticatedSpaceRecordError(.badRequest, code: "InvalidRequest")
        }
        guard let lease = capability.jsonReadAdmission.reserve(
            maximumResponseBytes: PublicRepositoryJSONReadLimits
                .maximumGetRecordResponseBytes
        ) else {
            return authenticatedSpaceRecordError(.serviceUnavailable, code: "temporarily_unavailable")
        }
        do {
            let output = try await handler.handle(parameters: parameters, input: (), context: request)
            return authenticatedGetRecordJSON(.ok, output, lease: lease)
        } catch let failure as AuthenticatedSpaceRecordFailure {
            lease.release()
            return authenticatedSpaceRecordResponse(for: failure, capability: capability)
        } catch {
            lease.release()
            return authenticatedSpaceRecordError(.serviceUnavailable, code: "temporarily_unavailable")
        }
    }
    registerAuthenticatedRecordWrongMethods(on: router, path: path)
}

func registerAuthenticatedListRecordsEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceRecordsCapability
) {
    let handler = AuthenticatedListRecordsHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.listRecords"
    router.get(path) { request, _ async -> Response in
        let parameters: ComAtprotoSpaceListRecords.Parameters
        do {
            parameters = try parseAuthenticatedListRecordsParameters(request)
        } catch {
            return authenticatedSpaceRecordError(.badRequest, code: "InvalidRequest")
        }
        guard let lease = capability.jsonReadAdmission.reserve(
            maximumResponseBytes: PublicRepositoryJSONReadLimits
                .maximumListRecordsResponseBytes
        ) else {
            return authenticatedSpaceRecordError(.serviceUnavailable, code: "temporarily_unavailable")
        }
        do {
            let output = try await handler.handle(parameters: parameters, input: (), context: request)
            return authenticatedListRecordsJSON(.ok, output, lease: lease)
        } catch let failure as AuthenticatedSpaceRecordFailure {
            lease.release()
            return authenticatedSpaceRecordResponse(for: failure, capability: capability)
        } catch {
            lease.release()
            return authenticatedSpaceRecordError(.serviceUnavailable, code: "temporarily_unavailable")
        }
    }
    registerAuthenticatedRecordWrongMethods(on: router, path: path)
}

private func authorize(
    _ authorizer: SwanOAuthResourceAuthorizer,
    request: Request,
    fixedPath: String,
    method: String = "GET"
) async throws -> AuthorizationContext {
    do {
        return try await authorizer.authorize(
            request: request,
            method: method,
            fixedPath: fixedPath
        )
    } catch let failure as SwanResourceAuthorizationFailure {
        throw switch failure {
        case .nonceChallengeRequired: AuthenticatedSpaceRecordFailure.nonceChallenge
        case .denied: AuthenticatedSpaceRecordFailure.denied
        case .unavailable: AuthenticatedSpaceRecordFailure.unavailable
        }
    } catch {
        throw AuthenticatedSpaceRecordFailure.unavailable
    }
}

/// Selects the authenticated read mechanism without allowing the two bearer
/// formats to bleed into one another. `Bearer` is reserved for a compact
/// space credential and does not require or inspect DPoP. Any other scheme,
/// including the established `DPoP` OAuth scheme, stays on the exact
/// OAuth/DPoP authorizer and retains its nonce/replay behavior.
private func authorizeRecordRead(
    _ capability: SwanAuthenticatedSpaceRecordsCapability,
    request: Request,
    expectedSpace: SpaceURI,
    fixedPath: String
) async throws -> AuthorizationContext {
    let bearerToken: String?
    do {
        bearerToken = try spaceCredentialSchemeToken(from: request.headers)
    } catch {
        throw AuthenticatedSpaceRecordFailure.denied
    }
    if let token = bearerToken {
        guard let credentialAuthorizer = capability.credentialAuthorizer else {
            throw AuthenticatedSpaceRecordFailure.denied
        }
        do {
            return try await credentialAuthorizer.authorization(
                for: token,
                expectedSpace: expectedSpace,
                now: Date()
            )
        } catch let error as SwanError {
            if case .unavailable = error {
                throw AuthenticatedSpaceRecordFailure.unavailable
            }
            throw AuthenticatedSpaceRecordFailure.denied
        } catch {
            throw AuthenticatedSpaceRecordFailure.denied
        }
    }
    return try await authorize(
        capability.authorizer,
        request: request,
        fixedPath: fixedPath
    )
}

/// Write routes deliberately map OAuth/DPoP failures into the write failure
/// domain.  Reusing the read helper would throw `AuthenticatedSpaceRecordFailure`,
/// which the write route's catch-all would otherwise mislabel as malformed
/// input (400) instead of an authorization denial or nonce challenge.
private func authorizeWrite(
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
        case .nonceChallengeRequired: AuthenticatedSpaceWriteFailure.nonceChallenge
        case .denied: AuthenticatedSpaceWriteFailure.denied
        case .unavailable: AuthenticatedSpaceWriteFailure.unavailable
        }
    } catch {
        throw AuthenticatedSpaceWriteFailure.unavailable
    }
}

// MARK: - Authenticated permissioned record writes

/// A deliberately conservative cap for JSON XRPC write bodies. Record and
/// blob transfer use different streaming endpoints; accepting a large record
/// here would make this control-plane path an accidental buffering surface.
let authenticatedSpaceWriteMaximumJSONBytes = 1 * 1024 * 1024
private let authenticatedSpaceWriteMaximumOperations =
    SpaceWriteLimits.maximumOperations

private enum AuthenticatedSpaceWriteFailure: Error {
    case invalidRequest
    case spaceNotFound
    case denied
    case nonceChallenge
    case conflict
    case unavailable
}

private struct AuthenticatedCreateRecordHandler: ComAtprotoSpaceCreateRecord.ServerHandler {
    typealias Context = Request
    let capability: SwanAuthenticatedSpaceRecordsCapability

    func handle(parameters: Void, input: ComAtprotoSpaceCreateRecord.Input, context request: Request) async throws -> ComAtprotoSpaceCreateRecord.Output {
        let rkey = if let supplied = input.rkey {
            supplied
        } else {
            try RecordKey(keyString: try await capability.tidAllocator.next().toString())
        }
        let uri = try makeWriteURI(
            space: input.space,
            repo: input.repo,
            collection: input.collection,
            rkey: rkey
        )
        let value = try canonicalRecordValue(input.record)
        let authorization = try await authorizeWrite(
            capability.authorizer, request: request,
            fixedPath: "/xrpc/com.atproto.space.createRecord", method: "POST"
        )
        try requireSelfWrite(authorization, author: uri.author)
        let result = try await applyWrite(
            capability: capability, space: uri.space, author: uri.author,
            writes: [.create(uri: uri, value: value)], authorization: authorization
        )
        guard result.count == 1, result[0].action == .create,
              let cid = result[0].cid, result[0].uri == uri else {
            throw AuthenticatedSpaceWriteFailure.unavailable
        }
        return try ComAtprotoSpaceCreateRecord.Output(
            uri: ATProtocolURI(uriString: uri.rawValue), cid: CID.parse(cid)
        )
    }
}

private struct AuthenticatedPutRecordHandler: ComAtprotoSpacePutRecord.ServerHandler {
    typealias Context = Request
    let capability: SwanAuthenticatedSpaceRecordsCapability

    func handle(parameters: Void, input: ComAtprotoSpacePutRecord.Input, context request: Request) async throws -> ComAtprotoSpacePutRecord.Output {
        let uri = try makeWriteURI(space: input.space, repo: input.repo, collection: input.collection, rkey: input.rkey)
        let value = try canonicalRecordValue(input.record)
        let authorization = try await authorizeWrite(
            capability.authorizer, request: request,
            fixedPath: "/xrpc/com.atproto.space.putRecord", method: "POST"
        )
        try requireSelfWrite(authorization, author: uri.author)
        let result = try await applyWrite(
            capability: capability, space: uri.space, author: uri.author,
            writes: [.put(uri: uri, value: value)], authorization: authorization
        )
        guard result.count == 1,
              result[0].action == .create || result[0].action == .update,
              let cid = result[0].cid, result[0].uri == uri else {
            throw AuthenticatedSpaceWriteFailure.unavailable
        }
        return try ComAtprotoSpacePutRecord.Output(
            uri: ATProtocolURI(uriString: uri.rawValue), cid: CID.parse(cid)
        )
    }
}

private struct AuthenticatedDeleteRecordHandler: ComAtprotoSpaceDeleteRecord.ServerHandler {
    typealias Context = Request
    let capability: SwanAuthenticatedSpaceRecordsCapability

    func handle(parameters: Void, input: ComAtprotoSpaceDeleteRecord.Input, context request: Request) async throws -> ComAtprotoSpaceDeleteRecord.Output {
        let uri = try makeWriteURI(space: input.space, repo: input.repo, collection: input.collection, rkey: input.rkey)
        let authorization = try await authorizeWrite(
            capability.authorizer, request: request,
            fixedPath: "/xrpc/com.atproto.space.deleteRecord", method: "POST"
        )
        try requireSelfWrite(authorization, author: uri.author)
        let result = try await applyWrite(
            capability: capability, space: uri.space, author: uri.author,
            writes: [.delete(uri: uri)], authorization: authorization
        )
        guard result.count == 1, result[0].action == .delete, result[0].uri == uri else {
            throw AuthenticatedSpaceWriteFailure.unavailable
        }
        return .init()
    }
}

private struct AuthenticatedApplyWritesHandler: ComAtprotoSpaceApplyWrites.ServerHandler {
    typealias Context = Request
    let capability: SwanAuthenticatedSpaceRecordsCapability

    func handle(parameters: Void, input: ComAtprotoSpaceApplyWrites.Input, context request: Request) async throws -> ComAtprotoSpaceApplyWrites.Output {
        guard !input.writes.isEmpty,
              input.writes.count <= authenticatedSpaceWriteMaximumOperations
        else { throw AuthenticatedSpaceWriteFailure.invalidRequest }
        let space: SpaceURI
        let author: String
        do { space = try SpaceURI(input.space.uriString()); author = input.repo.didString() }
        catch { throw AuthenticatedSpaceWriteFailure.invalidRequest }
        var writes: [AuthorizedSpaceRepositoryWrite] = []
        writes.reserveCapacity(input.writes.count)
        for write in input.writes {
            switch write {
            case let .comAtprotoSpaceApplyWritesCreate(create):
                let rkey = if let supplied = create.rkey {
                    supplied
                } else {
                    try RecordKey(keyString: try await capability.tidAllocator.next().toString())
                }
                writes.append(.create(
                    uri: try makeWriteURI(space: input.space, repo: input.repo, collection: create.collection, rkey: rkey),
                    value: try canonicalRecordValue(create.value)
                ))
            case let .comAtprotoSpaceApplyWritesUpdate(update):
                writes.append(.update(
                    uri: try makeWriteURI(space: input.space, repo: input.repo, collection: update.collection, rkey: update.rkey),
                    value: try canonicalRecordValue(update.value)
                ))
            case let .comAtprotoSpaceApplyWritesDelete(delete):
                writes.append(.delete(uri: try makeWriteURI(space: input.space, repo: input.repo, collection: delete.collection, rkey: delete.rkey)))
            case .unexpected:
                throw AuthenticatedSpaceWriteFailure.invalidRequest
            }
        }
        let authorization = try await authorizeWrite(
            capability.authorizer, request: request,
            fixedPath: "/xrpc/com.atproto.space.applyWrites", method: "POST"
        )
        try requireSelfWrite(authorization, author: author)
        let results = try await applyWrite(
            capability: capability, space: space, author: author, writes: writes, authorization: authorization
        )
        guard results.count == writes.count else { throw AuthenticatedSpaceWriteFailure.unavailable }
        let output = try results.map { result -> ComAtprotoSpaceApplyWrites.OutputResultsUnion in
            switch result.action {
            case .create:
                guard let cid = result.cid else { throw AuthenticatedSpaceWriteFailure.unavailable }
                return .comAtprotoSpaceApplyWritesCreateResult(.init(uri: try ATProtocolURI(uriString: result.uri.rawValue), cid: try CID.parse(cid), validationStatus: nil))
            case .update:
                guard let cid = result.cid else { throw AuthenticatedSpaceWriteFailure.unavailable }
                return .comAtprotoSpaceApplyWritesUpdateResult(.init(uri: try ATProtocolURI(uriString: result.uri.rawValue), cid: try CID.parse(cid), validationStatus: nil))
            case .delete:
                return .comAtprotoSpaceApplyWritesDeleteResult(.init())
            }
        }
        return .init(results: output)
    }
}

private func requireSelfWrite(_ authorization: AuthorizationContext, author: String) throws {
    guard case let .accountOAuth(subject, _) = authorization, subject == author else {
        throw AuthenticatedSpaceWriteFailure.spaceNotFound
    }
}

private func makeWriteURI(space: ATProtocolURI, repo: DID, collection: NSID, rkey: RecordKey) throws -> SpaceRecordURI {
    try SpaceRecordURI(space: SpaceURI(space.uriString()), author: repo.didString(), collection: collection.nsidString(), rkey: rkey.value)
}

private func canonicalRecordValue(_ record: ATProtocolValueContainer) throws -> Data {
    let cborValue = try record.toCBORValue()
    let recordType: String?
    switch record {
    case let .object(fields): recordType = fields["$type"].flatMap { if case let .string(value) = $0 { value } else { nil } }
    case let .unknownType(value, _): recordType = value
    case let .knownType(value): recordType = Swift.type(of: value).typeIdentifier
    default: recordType = nil
    }
    guard recordType?.utf8.count ?? 1 > 0,
          cborValue is OrderedCBORMap || cborValue is [String: Any] else {
        throw AuthenticatedSpaceWriteFailure.invalidRequest
    }
    let bytes = try DAGCBOR.encodeValue(cborValue)
    _ = try CID.parse(CID.fromDAGCBOR(bytes).string)
    // Refuse a future encoder regression that emits non-record root values.
    _ = try CARRepository.decodeRecordCBOR(bytes)
    return bytes
}

private func applyWrite(
    capability: SwanAuthenticatedSpaceRecordsCapability,
    space: SpaceURI,
    author: String,
    writes: [AuthorizedSpaceRepositoryWrite],
    authorization: AuthorizationContext
) async throws -> [AuthorizedSpaceRepositoryWriteResult] {
    do {
        func seedAllocatorFromDurableState() async throws {
            let currentRevision = try await capability.directory.repositoryWriteWireRevision(
                space: space,
                author: author,
                writes: writes,
                authorization: authorization
            )
            if let currentRevision,
               let currentTID = try? TID(tidString: currentRevision) {
                await capability.tidAllocator.observe(currentTID)
            }
        }
        let requestID = UUID()
        try await seedAllocatorFromDurableState()
        do {
            return try await capability.directory.apply(
                space: space, author: author, writes: writes, requestID: requestID,
                wireRevision: try await capability.tidAllocator.next().toString(),
                authorization: authorization
            )
        } catch let error as SwanError {
            // A concurrent writer can commit after the seed read but before
            // this transaction. Retry only the durable monotonicity failure;
            // all validation, authorization, and CAS errors remain visible
            // to the normal XRPC mapping.
            guard case let .malformed(message) = error,
                  message == "wire revision must advance" else {
                throw error
            }
            try await seedAllocatorFromDurableState()
            return try await capability.directory.apply(
                space: space, author: author, writes: writes, requestID: requestID,
                wireRevision: try await capability.tidAllocator.next().toString(),
                authorization: authorization
            )
        }
    } catch let error as SwanError {
        if case .conflict = error { throw AuthenticatedSpaceWriteFailure.conflict }
        if case .unauthorized = error { throw AuthenticatedSpaceWriteFailure.denied }
        if case .malformed = error { throw AuthenticatedSpaceWriteFailure.invalidRequest }
        throw AuthenticatedSpaceWriteFailure.unavailable
    } catch {
        throw AuthenticatedSpaceWriteFailure.unavailable
    }
}

func registerAuthenticatedCreateRecordEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceRecordsCapability
) {
    let handler = AuthenticatedCreateRecordHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.createRecord"
    router.post(path) { request, context async -> Response in
        await withAuthenticatedSpaceWriteInput(
            request,
            context: context,
            as: ComAtprotoSpaceCreateRecord.Input.self,
            capability: capability
        ) { input in
            authenticatedSpaceWriteJSON(
                .ok,
                try await handler.handle(parameters: (), input: input, context: request)
            )
        }
    }
    registerAuthenticatedWriteWrongMethods(on: router, path: path)
}

func registerAuthenticatedPutRecordEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceRecordsCapability
) {
    let handler = AuthenticatedPutRecordHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.putRecord"
    router.post(path) { request, context async -> Response in
        await withAuthenticatedSpaceWriteInput(
            request,
            context: context,
            as: ComAtprotoSpacePutRecord.Input.self,
            capability: capability
        ) { input in
            authenticatedSpaceWriteJSON(
                .ok,
                try await handler.handle(parameters: (), input: input, context: request)
            )
        }
    }
    registerAuthenticatedWriteWrongMethods(on: router, path: path)
}

func registerAuthenticatedDeleteRecordEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceRecordsCapability
) {
    let handler = AuthenticatedDeleteRecordHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.deleteRecord"
    router.post(path) { request, context async -> Response in
        await withAuthenticatedSpaceWriteInput(
            request,
            context: context,
            as: ComAtprotoSpaceDeleteRecord.Input.self,
            capability: capability
        ) { input in
            authenticatedSpaceWriteJSON(
                .ok,
                try await handler.handle(parameters: (), input: input, context: request)
            )
        }
    }
    registerAuthenticatedWriteWrongMethods(on: router, path: path)
}

func registerAuthenticatedApplyWritesEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceRecordsCapability
) {
    let handler = AuthenticatedApplyWritesHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.applyWrites"
    router.post(path) { request, context async -> Response in
        await withAuthenticatedSpaceWriteInput(
            request,
            context: context,
            as: ComAtprotoSpaceApplyWrites.Input.self,
            capability: capability
        ) { input in
            authenticatedSpaceWriteJSON(
                .ok,
                try await handler.handle(parameters: (), input: input, context: request)
            )
        }
    }
    registerAuthenticatedWriteWrongMethods(on: router, path: path)
}

private func withAuthenticatedSpaceWriteInput<Value: Decodable>(
    _ request: Request,
    context: SwanHTTPRequestContext,
    as type: Value.Type,
    capability: SwanAuthenticatedSpaceRecordsCapability,
    operation: (Value) async throws -> Response
) async -> Response {
    let contentTypes = request.headers[values: .contentType]
    guard contentTypes.count == 1,
          contentTypes[0].split(separator: ";", maxSplits: 1).first?
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "application/json"
    else {
        context.jsonWriteBodyTermination.terminate()
        return authenticatedSpaceWriteResponse(
            for: .invalidRequest,
            capability: capability
        )
    }
    guard acceptsAuthenticatedSpaceWriteContentLength(request.headers[values: .contentLength]) else {
        context.jsonWriteBodyTermination.terminate()
        return authenticatedSpaceWriteResponse(
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
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw AuthenticatedSpaceWriteFailure.invalidRequest
        }
    } operation: { input in
        try await operation(input)
    } errorResponse: { error in
        authenticatedSpaceWriteResponse(for: error, capability: capability)
    }
}

func acceptsAuthenticatedSpaceWriteContentLength(_ values: [String]) -> Bool {
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

private func authenticatedSpaceWriteResponse(
    for error: any Error,
    capability: SwanAuthenticatedSpaceRecordsCapability
) -> Response {
    if let failure = error as? AuthenticatedSpaceWriteFailure {
        return authenticatedSpaceWriteResponse(for: failure, capability: capability)
    }
    if let failure = error as? SwanJSONWriteBodyCollectionFailure {
        return authenticatedSpaceWriteResponse(for: failure)
    }
    return authenticatedSpaceWriteError(.badRequest, code: "InvalidRequest")
}

private func authenticatedSpaceWriteResponse(
    for failure: SwanJSONWriteBodyCollectionFailure
) -> Response {
    switch failure {
    case .invalidRequest:
        authenticatedSpaceWriteError(.badRequest, code: "InvalidRequest")
    case .unavailable:
        authenticatedSpaceWriteError(.serviceUnavailable, code: "temporarily_unavailable")
    }
}

private func registerAuthenticatedWriteWrongMethods(
    on router: Router<BasicRequestContext>, path: RouterPath
) {
    for method: HTTPRequest.Method in [.get, .head, .put, .patch, .delete, .options, .connect, .trace] {
        router.on(path, method: method) { _, _ -> Response in
            authenticatedSpaceWriteError(.notFound, code: "permissioned_endpoint_unavailable")
        }
    }
}

private func authenticatedSpaceWriteResponse(
    for failure: AuthenticatedSpaceWriteFailure,
    capability: SwanAuthenticatedSpaceRecordsCapability
) -> Response {
    switch failure {
    case .invalidRequest: authenticatedSpaceWriteError(.badRequest, code: "InvalidRequest")
    case .spaceNotFound: authenticatedSpaceWriteError(.notFound, code: "SpaceNotFound")
    case .denied: authenticatedSpaceWriteError(.unauthorized, code: "Unauthorized")
    case .nonceChallenge: authenticatedGetSpaceNonceChallenge(authorizer: capability.authorizer)
    case .conflict: authenticatedSpaceWriteError(.conflict, code: "ConcurrentWrite")
    case .unavailable: authenticatedSpaceWriteError(.serviceUnavailable, code: "temporarily_unavailable")
    }
}

private func authenticatedSpaceWriteError(_ status: HTTPResponse.Status, code: String) -> Response {
    authenticatedGetSpaceJSON(status, ["error": code])
}

private func authenticatedSpaceWriteJSON(_ status: HTTPResponse.Status, _ output: some Encodable) -> Response {
    authenticatedGetSpaceJSON(status, output)
}

/// `JSONDecoder` intentionally follows Foundation's permissive duplicate-key
/// behavior. XRPC bodies are signed-and-applied commands, so accept each key
/// exactly once at every object level before handing the same bytes to the
/// generated `Decodable` input contract.
enum StrictPermissionedWriteJSON {
    static func validate(_ data: Data) throws {
        guard !data.isEmpty, data.count <= authenticatedSpaceWriteMaximumJSONBytes else {
            throw AuthenticatedSpaceWriteFailure.invalidRequest
        }
        var parser = Parser(bytes: Array(data))
        try parser.value(depth: 0)
        parser.whitespace()
        guard parser.index == parser.bytes.count else { throw AuthenticatedSpaceWriteFailure.invalidRequest }
    }

    private struct Parser {
        let bytes: [UInt8]
        var index = 0

        mutating func whitespace() {
            while index < bytes.count, bytes[index] == 0x20 || bytes[index] == 0x0a || bytes[index] == 0x0d || bytes[index] == 0x09 { index += 1 }
        }

        mutating func value(depth: Int) throws {
            guard depth < 64 else { throw AuthenticatedSpaceWriteFailure.invalidRequest }
            whitespace()
            guard index < bytes.count else { throw AuthenticatedSpaceWriteFailure.invalidRequest }
            switch bytes[index] {
            case 0x7b: try object(depth: depth + 1)
            case 0x5b: try array(depth: depth + 1)
            case 0x22: _ = try string()
            case 0x74, 0x66, 0x6e: try atom()
            case 0x2d, 0x30 ... 0x39: try atom()
            default: throw AuthenticatedSpaceWriteFailure.invalidRequest
            }
        }

        mutating func object(depth: Int) throws {
            index += 1 // {
            whitespace()
            if consume(0x7d) { return }
            var keys = Set<String>()
            while true {
                whitespace()
                let key = try string()
                guard keys.insert(key).inserted else { throw AuthenticatedSpaceWriteFailure.invalidRequest }
                whitespace()
                guard consume(0x3a) else { throw AuthenticatedSpaceWriteFailure.invalidRequest }
                try value(depth: depth)
                whitespace()
                if consume(0x7d) { return }
                guard consume(0x2c) else { throw AuthenticatedSpaceWriteFailure.invalidRequest }
            }
        }

        mutating func array(depth: Int) throws {
            index += 1 // [
            whitespace()
            if consume(0x5d) { return }
            while true {
                try value(depth: depth)
                whitespace()
                if consume(0x5d) { return }
                guard consume(0x2c) else { throw AuthenticatedSpaceWriteFailure.invalidRequest }
            }
        }

        mutating func string() throws -> String {
            guard consume(0x22) else { throw AuthenticatedSpaceWriteFailure.invalidRequest }
            let start = index - 1
            var escaped = false
            while index < bytes.count {
                let byte = bytes[index]
                index += 1
                if escaped { escaped = false; continue }
                if byte == 0x5c { escaped = true; continue }
                if byte == 0x22 {
                    let encoded = Data(bytes[start ..< index])
                    guard let value = try? JSONDecoder().decode(String.self, from: encoded) else {
                        throw AuthenticatedSpaceWriteFailure.invalidRequest
                    }
                    return value
                }
                guard byte >= 0x20 else { throw AuthenticatedSpaceWriteFailure.invalidRequest }
            }
            throw AuthenticatedSpaceWriteFailure.invalidRequest
        }

        mutating func atom() throws {
            let start = index
            while index < bytes.count, ![0x20, 0x0a, 0x0d, 0x09, 0x2c, 0x5d, 0x7d].contains(bytes[index]) { index += 1 }
            guard index > start else { throw AuthenticatedSpaceWriteFailure.invalidRequest }
        }

        mutating func consume(_ byte: UInt8) -> Bool {
            guard index < bytes.count, bytes[index] == byte else { return false }
            index += 1
            return true
        }
    }
}

private func registerAuthenticatedRecordWrongMethods(
    on router: Router<BasicRequestContext>,
    path: RouterPath
) {
    for method: HTTPRequest.Method in [.head, .post, .put, .patch, .delete, .options, .connect, .trace] {
        router.on(path, method: method) { _, _ -> Response in
            authenticatedSpaceRecordError(.notFound, code: "permissioned_endpoint_unavailable")
        }
    }
}

private func parseAuthenticatedGetRecordParameters(
    _ request: Request
) throws -> ComAtprotoSpaceGetRecord.Parameters {
    let query = try strictAuthenticatedRecordQuery(
        request,
        required: ["space", "repo", "collection", "rkey"],
        optional: []
    )
    let space = try ATProtocolURI(uriString: try requiredQueryValue("space", in: query, maximumBytes: 2_048))
    let repo = try DID(didString: try requiredQueryValue("repo", in: query, maximumBytes: 2_048))
    let collection = try NSID(nsidString: try requiredQueryValue("collection", in: query, maximumBytes: 317))
    let rkey = try RecordKey(keyString: try requiredQueryValue("rkey", in: query, maximumBytes: 512))
    // Petrel's generic AT URI parser intentionally accepts broad AT syntax;
    // make the domain parser part of request validation before OAuth work.
    _ = try SpaceRecordURI(
        space: try SpaceURI(space.uriString()),
        author: repo.didString(),
        collection: collection.nsidString(),
        rkey: rkey.value
    )
    return .init(space: space, repo: repo, collection: collection, rkey: rkey)
}

private func parseAuthenticatedListRecordsParameters(
    _ request: Request
) throws -> ComAtprotoSpaceListRecords.Parameters {
    let query = try strictAuthenticatedRecordQuery(
        request,
        required: ["space", "repo"],
        optional: ["collection", "limit", "cursor", "reverse", "excludeValues"]
    )
    let space = try ATProtocolURI(uriString: try requiredQueryValue("space", in: query, maximumBytes: 2_048))
    let repo = try DID(didString: try requiredQueryValue("repo", in: query, maximumBytes: 2_048))
    let collection = try query["collection"].map { try NSID(nsidString: bounded($0, maximumBytes: 317)) }
    let limit = try query["limit"].map(strictRecordPageLimit)
    let cursor = try query["cursor"].map { try bounded($0, maximumBytes: 1_024) }
    let reverse = try query["reverse"].map(strictBoolean)
    let excludeValues = try query["excludeValues"].map(strictBoolean)
    _ = try SpaceRecordURI(
        space: try SpaceURI(space.uriString()),
        author: repo.didString(),
        collection: collection?.nsidString() ?? "app.swan.records",
        rkey: "scope"
    )
    return .init(
        space: space,
        repo: repo,
        collection: collection,
        limit: limit,
        cursor: cursor,
        reverse: reverse,
        excludeValues: excludeValues
    )
}

func strictAuthenticatedRecordQuery(
    _ request: Request,
    required: Set<String>,
    optional: Set<String>
) throws -> [String: String] {
    guard !request.uri.string.contains("#"),
          let query = request.uri.query,
          !query.isEmpty,
          query.utf8.count <= 8 * 1_024 else {
        throw AuthenticatedSpaceRecordFailure.invalidRequest
    }
    let allowed = required.union(optional)
    var decoded: [String: String] = [:]
    for segment in query.split(separator: "&", omittingEmptySubsequences: false) {
        let pair = segment.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        guard pair.count == 2,
              !pair[0].isEmpty,
              pair[0].utf8.allSatisfy({ ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z")) || ($0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z")) }),
              allowed.contains(String(pair[0])),
              decoded[String(pair[0])] == nil else {
            throw AuthenticatedSpaceRecordFailure.invalidRequest
        }
        decoded[String(pair[0])] = try strictQueryDecode(pair[1])
    }
    guard required.allSatisfy({ decoded[$0] != nil }) else {
        throw AuthenticatedSpaceRecordFailure.invalidRequest
    }
    return decoded
}

func requiredQueryValue(
    _ name: String,
    in query: [String: String],
    maximumBytes: Int
) throws -> String {
    guard let value = query[name] else {
        throw AuthenticatedSpaceRecordFailure.invalidRequest
    }
    return try bounded(value, maximumBytes: maximumBytes)
}

func bounded(_ value: String, maximumBytes: Int) throws -> String {
    guard !value.isEmpty, value.utf8.count <= maximumBytes else {
        throw AuthenticatedSpaceRecordFailure.invalidRequest
    }
    return value
}

private func strictRecordPageLimit(_ value: String) throws -> Int {
    guard !value.isEmpty,
          value.utf8.allSatisfy({ $0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9") }),
          let limit = Int(value),
          (1 ... 100).contains(limit) else {
        throw AuthenticatedSpaceRecordFailure.invalidRequest
    }
    return limit
}

func strictBoolean(_ value: String) throws -> Bool {
    switch value {
    case "true": return true
    case "false": return false
    default: throw AuthenticatedSpaceRecordFailure.invalidRequest
    }
}

private func authenticatedSpaceRecordResponse(
    for failure: AuthenticatedSpaceRecordFailure,
    capability: SwanAuthenticatedSpaceRecordsCapability
) -> Response {
    switch failure {
    case .invalidRequest:
        authenticatedSpaceRecordError(.badRequest, code: "InvalidRequest")
    case .spaceNotFound:
        authenticatedSpaceRecordError(.notFound, code: "SpaceNotFound")
    case .recordNotFound:
        authenticatedSpaceRecordError(.notFound, code: "RecordNotFound")
    case .denied:
        authenticatedSpaceRecordError(.unauthorized, code: "Unauthorized")
    case .nonceChallenge:
        authenticatedGetSpaceNonceChallenge(authorizer: capability.authorizer)
    case .unavailable:
        authenticatedSpaceRecordError(.serviceUnavailable, code: "temporarily_unavailable")
    }
}

private func authenticatedSpaceRecordError(
    _ status: HTTPResponse.Status,
    code: String
) -> Response {
    authenticatedGetSpaceJSON(status, ["error": code])
}

/// The generated `Record` encoder carries a `$type` framing field used for
/// generic lexicon values. These XRPC schemas declare plain objects, so the
/// HTTP adapter intentionally serializes a small wire projection while still
/// using the generated `ServerHandler` input/output contracts above.
private struct GetRecordWireOutput: Encodable {
    let uri: String
    let cid: String
    let value: ATProtocolValueContainer
}

private struct ListRecordWireOutput: Encodable {
    let collection: String
    let rkey: String
    let cid: String
    let value: ATProtocolValueContainer?
}

private struct ListRecordsWireOutput: Encodable {
    let cursor: String?
    let records: [ListRecordWireOutput]
}

private func authenticatedGetRecordJSON(
    _ status: HTTPResponse.Status,
    _ output: ComAtprotoSpaceGetRecord.Output,
    lease: PublicRepositoryJSONReadLease? = nil
) -> Response {
    authenticatedGetSpaceJSON(
        status,
        GetRecordWireOutput(
            uri: output.uri.uriString(),
            cid: output.cid.string,
            value: output.value
        ),
        maximumBytes: PublicRepositoryJSONReadLimits.maximumGetRecordResponseBytes,
        lease: lease
    )
}

private func authenticatedListRecordsJSON(
    _ status: HTTPResponse.Status,
    _ output: ComAtprotoSpaceListRecords.Output,
    lease: PublicRepositoryJSONReadLease? = nil
) -> Response {
    authenticatedGetSpaceJSON(
        status,
        ListRecordsWireOutput(
            cursor: output.cursor,
            records: output.records.map {
                ListRecordWireOutput(
                    collection: $0.collection.nsidString(),
                    rkey: $0.rkey.value,
                    cid: $0.cid.string,
                    value: $0.value
                )
            }
        ),
        maximumBytes: PublicRepositoryJSONReadLimits.maximumListRecordsResponseBytes,
        lease: lease
    )
}
