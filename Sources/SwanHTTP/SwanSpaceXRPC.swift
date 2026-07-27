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

private func strictQueryDecode(_ encoded: Substring) throws -> String {
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

private func authenticatedGetSpaceNonceChallenge(
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

private func authenticatedGetSpaceJSON(
    _ status: HTTPResponse.Status,
    _ body: some Encodable
) -> Response {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = (try? encoder.encode(body)) ?? Data("{}".utf8)
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

    init(
        authorizer: SwanOAuthResourceAuthorizer,
        directory: any AuthorizedSpaceRepositoryDirectory
    ) {
        self.authorizer = authorizer
        self.directory = directory
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

        let authorization = try await authorize(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/com.atproto.space.getRecord"
        )
        guard case let .accountOAuth(subject, _) = authorization,
              subject == uri.author else {
            // The caller must never learn whether another account has a
            // repository, space, or record. The declared space-not-found
            // result is the reference endpoint's opaque closure.
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

        let authorization = try await authorize(
            capability.authorizer,
            request: request,
            fixedPath: "/xrpc/com.atproto.space.listRecords"
        )
        guard case let .accountOAuth(subject, _) = authorization,
              subject == repo else {
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
        do {
            let output = try await handler.handle(parameters: parameters, input: (), context: request)
            return authenticatedGetRecordJSON(.ok, output)
        } catch let failure as AuthenticatedSpaceRecordFailure {
            return authenticatedSpaceRecordResponse(for: failure, capability: capability)
        } catch {
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
        do {
            let output = try await handler.handle(parameters: parameters, input: (), context: request)
            return authenticatedListRecordsJSON(.ok, output)
        } catch let failure as AuthenticatedSpaceRecordFailure {
            return authenticatedSpaceRecordResponse(for: failure, capability: capability)
        } catch {
            return authenticatedSpaceRecordError(.serviceUnavailable, code: "temporarily_unavailable")
        }
    }
    registerAuthenticatedRecordWrongMethods(on: router, path: path)
}

private func authorize(
    _ authorizer: SwanOAuthResourceAuthorizer,
    request: Request,
    fixedPath: String
) async throws -> AuthorizationContext {
    do {
        return try await authorizer.authorize(
            request: request,
            method: "GET",
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

private func strictAuthenticatedRecordQuery(
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

private func requiredQueryValue(
    _ name: String,
    in query: [String: String],
    maximumBytes: Int
) throws -> String {
    guard let value = query[name] else {
        throw AuthenticatedSpaceRecordFailure.invalidRequest
    }
    return try bounded(value, maximumBytes: maximumBytes)
}

private func bounded(_ value: String, maximumBytes: Int) throws -> String {
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

private func strictBoolean(_ value: String) throws -> Bool {
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
    _ output: ComAtprotoSpaceGetRecord.Output
) -> Response {
    authenticatedGetSpaceJSON(
        status,
        GetRecordWireOutput(
            uri: output.uri.uriString(),
            cid: output.cid.string,
            value: output.value
        )
    )
}

private func authenticatedListRecordsJSON(
    _ status: HTTPResponse.Status,
    _ output: ComAtprotoSpaceListRecords.Output
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
        )
    )
}
