import Foundation
import Hummingbird
import HTTPTypes
import Petrel
import SwanCore
import SwanOAuth
import SwanSpaces

/// The complete capability for the generic PDS managing-app endpoint.  Its
/// construction deliberately makes storage access unrepresentable.
public struct SwanSimpleSpaceCheckUserAccessCapability: Sendable {
    let serviceAuthentication: any SpaceServiceAuthenticationVerifier
    let managingServiceAudience: String

    init(
        serviceAuthentication: any SpaceServiceAuthenticationVerifier,
        managingServiceAudience: String
    ) {
        self.serviceAuthentication = serviceAuthentication
        self.managingServiceAudience = managingServiceAudience
    }
}

private enum SimpleSpaceCheckUserAccessFailure: Error {
    case denied
    case unavailable
}

private struct SimpleSpaceCheckUserAccessHandler:
    ComAtprotoSimplespaceCheckUserAccess.ServerHandler
{
    typealias Context = Request

    let capability: SwanSimpleSpaceCheckUserAccessCapability

    func handle(
        parameters: ComAtprotoSimplespaceCheckUserAccess.Parameters,
        input: Void,
        context request: Request
    ) async throws -> ComAtprotoSimplespaceCheckUserAccess.Output {
        // Parse the generated values again through the narrower domain types
        // before service authentication. Neither result is used for policy;
        // this only rejects non-canonical requests without consulting storage.
        do {
            _ = try SpaceURI(parameters.space.uriString())
            _ = try DID(didString: parameters.user.didString())
        } catch {
            throw SimpleSpaceCheckUserAccessFailure.denied
        }
        do {
            let compact = try exactSpaceServiceBearerToken(from: request.headers)
            _ = try await capability.serviceAuthentication.authenticate(
                compact,
                expectedAudience: capability.managingServiceAudience,
                expectedMethod: ComAtprotoSimplespaceCheckUserAccess.typeIdentifier,
                expectedRequestBodyDigest: nil,
                now: Date()
            )
        } catch let error as SwanError {
            if case .unavailable = error {
                throw SimpleSpaceCheckUserAccessFailure.unavailable
            }
            throw SimpleSpaceCheckUserAccessFailure.denied
        } catch {
            throw SimpleSpaceCheckUserAccessFailure.denied
        }
        // The pinned PDS is not an application policy engine. A successful
        // service authentication therefore proves only the caller identity;
        // it never reaches authority, membership, record, or blob state.
        return .init(authorized: false)
    }
}

func registerSimpleSpaceCheckUserAccessEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanSimpleSpaceCheckUserAccessCapability
) {
    let handler = SimpleSpaceCheckUserAccessHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.simplespace.checkUserAccess"
    router.get(path) { request, _ async -> Response in
        do {
            let parameters = try parseSimpleSpaceCheckUserAccessParameters(request)
            let output = try await handler.handle(parameters: parameters, input: (), context: request)
            return simpleSpaceCheckUserAccessJSON(.ok, output)
        } catch let failure as SimpleSpaceCheckUserAccessFailure {
            return simpleSpaceCheckUserAccessResponse(for: failure)
        } catch {
            // Query syntax and generated-value conversion intentionally have
            // the same opaque response as bad service credentials.
            return simpleSpaceCheckUserAccessResponse(for: .denied)
        }
    }
    for method: HTTPRequest.Method in [.head, .post, .put, .patch, .delete, .options, .connect, .trace] {
        router.on(path, method: method) { _, _ -> Response in
            simpleSpaceCheckUserAccessError(.notFound, code: "permissioned_endpoint_unavailable")
        }
    }
}

private func parseSimpleSpaceCheckUserAccessParameters(
    _ request: Request
) throws -> ComAtprotoSimplespaceCheckUserAccess.Parameters {
    guard !request.uri.string.contains("#"),
          let query = request.uri.query,
          !query.isEmpty,
          query.utf8.count <= 4_096 else {
        throw SimpleSpaceCheckUserAccessFailure.denied
    }
    let allowed: Set<String> = ["space", "user", "access", "clientId"]
    var values: [String: String] = [:]
    for segment in query.split(separator: "&", omittingEmptySubsequences: false) {
        let pair = segment.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        guard pair.count == 2,
              !pair[0].isEmpty,
              pair[0].utf8.allSatisfy({ ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z")) || ($0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z")) }),
              allowed.contains(String(pair[0])),
              values[String(pair[0])] == nil else {
            throw SimpleSpaceCheckUserAccessFailure.denied
        }
        values[String(pair[0])] = try strictQueryDecode(pair[1])
    }
    guard let rawSpace = values["space"],
          let rawUser = values["user"],
          let rawAccess = values["access"],
          !rawSpace.isEmpty,
          !rawUser.isEmpty,
          (rawAccess == "read" || rawAccess == "write"),
          rawSpace.utf8.count <= 2_048,
          rawUser.utf8.count <= 2_048,
          values["clientId"].map({ !$0.isEmpty && $0.utf8.count <= 2_048 }) ?? true else {
        throw SimpleSpaceCheckUserAccessFailure.denied
    }
    if rawAccess == "write" && values["clientId"] != nil {
        throw SimpleSpaceCheckUserAccessFailure.denied
    }
    do {
        let space = try SpaceRef(uriString: rawSpace)
        let user = try DID(didString: rawUser)
        _ = try SpaceURI(space.uriString())
        return .init(space: space, user: user, access: rawAccess, clientId: values["clientId"])
    } catch {
        throw SimpleSpaceCheckUserAccessFailure.denied
    }
}

private func simpleSpaceCheckUserAccessResponse(
    for failure: SimpleSpaceCheckUserAccessFailure
) -> Response {
    switch failure {
    case .denied:
        simpleSpaceCheckUserAccessError(.unauthorized, code: "Unauthorized")
    case .unavailable:
        simpleSpaceCheckUserAccessError(.serviceUnavailable, code: "temporarily_unavailable")
    }
}

private func simpleSpaceCheckUserAccessError(
    _ status: HTTPResponse.Status,
    code: String
) -> Response {
    authenticatedGetSpaceJSON(status, ["error": code])
}

private func simpleSpaceCheckUserAccessJSON(
    _ status: HTTPResponse.Status,
    _ output: ComAtprotoSimplespaceCheckUserAccess.Output
) -> Response {
    authenticatedGetSpaceJSON(status, output)
}
