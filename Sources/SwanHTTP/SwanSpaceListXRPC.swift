import Foundation
import Hummingbird
import HTTPTypes
import Petrel
import SwanCore
import SwanSpaces
import SwanStorage

/// The distinct authenticated capability for local `listSpaces`. It has no
/// credential verifier by design: a bearer space credential is a cross-space
/// record read grant, never an account inventory grant.
public struct SwanAuthenticatedSpaceListCapability: Sendable {
    let authorizer: SwanOAuthResourceAuthorizer
    let directory: any AuthorizedHostedSpaceDirectory

    init(
        authorizer: SwanOAuthResourceAuthorizer,
        directory: any AuthorizedHostedSpaceDirectory
    ) {
        self.authorizer = authorizer
        self.directory = directory
    }
}

private enum AuthenticatedSpaceListFailure: Error {
    case invalidRequest
    case invalidCursor
    case denied
    case nonceChallenge
    case unavailable
}

private struct AuthenticatedListSpacesHandler {
    typealias Context = Request

    let capability: SwanAuthenticatedSpaceListCapability

    func handle(
        parameters: ComAtprotoSpaceListSpaces.Parameters,
        input: Void,
        context request: Request
    ) async throws -> ListSpacesWireOutput {
        let spaceType = parameters.spaceType?.nsidString()
        let authority = parameters.did?.didString()
        let cursor: SpaceURI?
        do {
            cursor = try parameters.cursor.map(SpaceURI.init)
            if let cursor {
                guard cursor.rawValue == parameters.cursor,
                      (spaceType == nil || cursor.spaceType == spaceType),
                      (authority == nil || cursor.authority == authority) else {
                    throw AuthenticatedSpaceListFailure.invalidCursor
                }
            }
        } catch let failure as AuthenticatedSpaceListFailure {
            throw failure
        } catch {
            throw AuthenticatedSpaceListFailure.invalidCursor
        }

        let authorization: AuthorizationContext
        do {
            authorization = try await capability.authorizer.authorizeSpaceRoute(
                request: request,
                method: "GET",
                fixedPath: "/xrpc/com.atproto.space.listSpaces"
            )
        } catch let failure as SwanResourceAuthorizationFailure {
            switch failure {
            case .nonceChallengeRequired:
                throw AuthenticatedSpaceListFailure.nonceChallenge
            case .denied:
                throw AuthenticatedSpaceListFailure.denied
            case .unavailable:
                throw AuthenticatedSpaceListFailure.unavailable
            }
        } catch {
            throw AuthenticatedSpaceListFailure.unavailable
        }
        // The LISTING FENCE (§6.1). `spaceType` / `authority` are already
        // `String?` here and the `?? "*"` defaulting lives in the matcher —
        // keep it there.
        //
        // This is a scope shortfall rendered as this route's own already-defined
        // opaque code (§6.5.8). `AuthenticatedSpaceListFailure` gains no new
        // case: a shortfall is indistinguishable on the wire from a bad token or
        // an inactive account, per `SwanOAuthResourceAuthorization.swift:9-16`
        // and §9-D6. The needed scope
        // (`SwanScopePermissions.spaceListingScopeNeeded(type:authority:)`) is
        // for server-side logs only and must never be echoed to the caller.
        guard case let .accountOAuth(subject, permissions) = authorization,
              permissions.allowsSpaceListing(
                  type: spaceType,
                  authority: authority
              ) else {
            throw AuthenticatedSpaceListFailure.denied
        }

        let page: AuthorizedHostedSpacePage
        do {
            page = try await capability.directory.hostedSpaces(
                .init(
                    subject: subject,
                    spaceType: spaceType,
                    authority: authority,
                    cursor: cursor,
                    limit: parameters.limit ?? 50
                ),
                authorization: authorization
            )
        } catch let error as SwanError {
            if case .unauthorized = error {
                throw AuthenticatedSpaceListFailure.denied
            }
            throw AuthenticatedSpaceListFailure.unavailable
        } catch {
            throw AuthenticatedSpaceListFailure.unavailable
        }

        return ListSpacesWireOutput(
            cursor: page.cursor?.rawValue,
            spaces: page.spaces.map {
                .init(
                    space: $0.space.rawValue,
                    repoRev: $0.repoRev,
                    data: $0.data.map(ListSpacesWireOutput.Bytes.init),
                    spaceRev: $0.spaceRev
                )
            }
        )
    }
}

func registerAuthenticatedListSpacesEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanAuthenticatedSpaceListCapability
) {
    let handler = AuthenticatedListSpacesHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.listSpaces"
    router.get(path) { request, _ async -> Response in
        let parameters: ComAtprotoSpaceListSpaces.Parameters
        do {
            parameters = try parseAuthenticatedListSpacesParameters(request)
        } catch AuthenticatedSpaceListFailure.invalidCursor {
            return authenticatedGetSpaceJSON(.badRequest, ["error": "InvalidCursor"])
        } catch {
            return authenticatedGetSpaceJSON(.badRequest, ["error": "InvalidRequest"])
        }
        do {
            let output = try await handler.handle(parameters: parameters, input: (), context: request)
            return authenticatedGetSpaceJSON(.ok, output)
        } catch let failure as AuthenticatedSpaceListFailure {
            return authenticatedListSpacesResponse(failure, capability: capability)
        } catch {
            return authenticatedGetSpaceJSON(.serviceUnavailable, ["error": "temporarily_unavailable"])
        }
    }
    for method: HTTPRequest.Method in [.head, .post, .put, .patch, .delete, .options, .connect, .trace] {
        router.on(path, method: method) { _, _ -> Response in
            authenticatedGetSpaceJSON(.notFound, ["error": "permissioned_endpoint_unavailable"])
        }
    }
}

private func parseAuthenticatedListSpacesParameters(
    _ request: Request
) throws -> ComAtprotoSpaceListSpaces.Parameters {
    guard !request.uri.string.contains("#") else {
        throw AuthenticatedSpaceListFailure.invalidRequest
    }
    let query = request.uri.query
    guard query?.utf8.count ?? 0 <= 8 * 1_024 else {
        throw AuthenticatedSpaceListFailure.invalidRequest
    }
    var values: [String: String] = [:]
    if let query, !query.isEmpty {
        for segment in query.split(separator: "&", omittingEmptySubsequences: false) {
            let pair = segment.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            // November 12 renamed the authority filter to `spaceDid`.
            guard pair.count == 2,
                  let key = String(bytes: pair[0].utf8, encoding: .utf8),
                  ["spaceType", "spaceDid", "limit", "cursor"].contains(key),
                  !pair[1].isEmpty,
                  values[key] == nil else {
                throw AuthenticatedSpaceListFailure.invalidRequest
            }
            values[key] = try strictQueryDecode(pair[1])
        }
    } else if query != nil {
        throw AuthenticatedSpaceListFailure.invalidRequest
    }

    let spaceType = try values["spaceType"].map { try NSID(nsidString: bounded($0, maximumBytes: 317)) }
    let did = try values["spaceDid"].map { try DID(didString: bounded($0, maximumBytes: 2_048)) }
    let limit: Int?
    if let raw = values["limit"] {
        guard raw.utf8.allSatisfy({ $0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9") }),
              let parsed = Int(raw), (1 ... 100).contains(parsed) else {
            throw AuthenticatedSpaceListFailure.invalidRequest
        }
        limit = parsed
    } else {
        limit = nil
    }
    let cursor = try values["cursor"].map { try bounded($0, maximumBytes: 2_048) }
    if let cursor {
        let parsed = try SpaceURI(cursor)
        guard parsed.rawValue == cursor,
              (spaceType == nil || parsed.spaceType == spaceType?.nsidString()),
              (did == nil || parsed.authority == did?.didString()) else {
            throw AuthenticatedSpaceListFailure.invalidCursor
        }
    }
    return .init(spaceType: spaceType, did: did, limit: limit, cursor: cursor)
}

private func authenticatedListSpacesResponse(
    _ failure: AuthenticatedSpaceListFailure,
    capability: SwanAuthenticatedSpaceListCapability
) -> Response {
    switch failure {
    case .invalidRequest:
        authenticatedGetSpaceJSON(.badRequest, ["error": "InvalidRequest"])
    case .invalidCursor:
        authenticatedGetSpaceJSON(.badRequest, ["error": "InvalidCursor"])
    case .denied:
        authenticatedGetSpaceJSON(.unauthorized, ["error": "Unauthorized"])
    case .nonceChallenge:
        authenticatedGetSpaceNonceChallenge(authorizer: capability.authorizer)
    case .unavailable:
        authenticatedGetSpaceJSON(.serviceUnavailable, ["error": "temporarily_unavailable"])
    }
}

private struct ListSpacesWireOutput: Encodable {
    struct Bytes: Encodable {
        let value: Data

        init(_ value: Data) {
            self.value = value
        }

        private enum CodingKeys: String, CodingKey { case bytes = "$bytes" }

        func encode(to encoder: any Encoder) throws {
            var values = encoder.container(keyedBy: CodingKeys.self)
            try values.encode(
                value.base64EncodedString().replacingOccurrences(of: "=", with: ""),
                forKey: .bytes
            )
        }
    }

    struct Space: Encodable {
        let space: String
        let repoRev: String?
        let data: Bytes?
        let spaceRev: String?
    }

    let cursor: String?
    let spaces: [Space]
}
