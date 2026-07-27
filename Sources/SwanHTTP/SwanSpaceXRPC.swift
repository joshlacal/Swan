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
