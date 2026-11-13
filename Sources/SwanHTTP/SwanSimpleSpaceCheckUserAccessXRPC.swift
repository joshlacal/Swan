import Foundation
import Hummingbird
import HTTPTypes
import Petrel
import SwanCore
import SwanOAuth
import SwanSpaces

/// The complete capability for Swan's generic managing-app endpoint. Its
/// construction deliberately makes storage access unrepresentable.
public struct SwanManagedSpaceCheckAccessCapability: Sendable {
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

private enum ManagedSpaceCheckAccessFailure: Error {
    case denied
    case unavailable
}

/// `com.atproto.managedspace.checkAccess` parameters.
private struct ManagedSpaceCheckAccessParameters {
    let space: SpaceURI
    let repo: String?
    let clientId: String?
}

private struct ManagedSpaceCheckAccessOutput: Encodable {
    let read: Bool
    let write: Bool
}

private let managedSpaceCheckAccessNSID = "com.atproto.managedspace.checkAccess"

private struct ManagedSpaceCheckAccessHandler {
    let capability: SwanManagedSpaceCheckAccessCapability

    func handle(
        parameters _: ManagedSpaceCheckAccessParameters,
        request: Request
    ) async throws -> ManagedSpaceCheckAccessOutput {
        do {
            let compact = try exactSpaceServiceBearerToken(from: request.headers)
            _ = try await capability.serviceAuthentication.authenticate(
                compact,
                expectedAudience: capability.managingServiceAudience,
                expectedMethod: managedSpaceCheckAccessNSID,
                expectedRequestBodyDigest: nil,
                now: Date()
            )
        } catch let error as SwanError {
            if case .unavailable = error {
                throw ManagedSpaceCheckAccessFailure.unavailable
            }
            throw ManagedSpaceCheckAccessFailure.denied
        } catch {
            throw ManagedSpaceCheckAccessFailure.denied
        }
        // Swan is a PDS, not an application policy engine.
        return ManagedSpaceCheckAccessOutput(read: false, write: false)
    }
}

func registerManagedSpaceCheckAccessEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanManagedSpaceCheckAccessCapability
) {
    let handler = ManagedSpaceCheckAccessHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.managedspace.checkAccess"
    router.get(path) { request, _ async -> Response in
        do {
            let parameters = try parseManagedSpaceCheckAccessParameters(request)
            let output = try await handler.handle(parameters: parameters, request: request)
            return authenticatedGetSpaceJSON(.ok, output)
        } catch let failure as ManagedSpaceCheckAccessFailure {
            return managedSpaceCheckAccessResponse(for: failure)
        } catch {
            return managedSpaceCheckAccessResponse(for: .denied)
        }
    }
    for method: HTTPRequest.Method in [.head, .post, .put, .patch, .delete, .options, .connect, .trace] {
        router.on(path, method: method) { _, _ -> Response in
            managedSpaceCheckAccessError(.notFound, code: "permissioned_endpoint_unavailable")
        }
    }
}

private func parseManagedSpaceCheckAccessParameters(
    _ request: Request
) throws -> ManagedSpaceCheckAccessParameters {
    guard !request.uri.string.contains("#"),
          let query = request.uri.query,
          !query.isEmpty,
          query.utf8.count <= 4_096 else {
        throw ManagedSpaceCheckAccessFailure.denied
    }
    let allowed: Set<String> = ["space", "repo", "clientId"]
    var values: [String: String] = [:]
    for segment in query.split(separator: "&", omittingEmptySubsequences: false) {
        let pair = segment.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        guard pair.count == 2,
              !pair[0].isEmpty,
              pair[0].utf8.allSatisfy({ ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z")) || ($0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z")) }),
              allowed.contains(String(pair[0])),
              values[String(pair[0])] == nil else {
            throw ManagedSpaceCheckAccessFailure.denied
        }
        values[String(pair[0])] = try strictQueryDecode(pair[1])
    }
    guard let rawSpace = values["space"],
          !rawSpace.isEmpty,
          rawSpace.utf8.count <= 2_048,
          values["repo"].map({ !$0.isEmpty && $0.utf8.count <= 2_048 }) ?? true,
          values["clientId"].map({
              !$0.isEmpty && $0.utf8.count <= 2_048
                  && SpacePolicyValidation.isValidURI($0)
          }) ?? true else {
        throw ManagedSpaceCheckAccessFailure.denied
    }
    do {
        let space = try SpaceURI(SpaceRef(uriString: rawSpace).uriString())
        let repo = try values["repo"].map { try DID(didString: $0).didString() }
        return ManagedSpaceCheckAccessParameters(
            space: space, repo: repo, clientId: values["clientId"]
        )
    } catch {
        throw ManagedSpaceCheckAccessFailure.denied
    }
}

private func managedSpaceCheckAccessResponse(
    for failure: ManagedSpaceCheckAccessFailure
) -> Response {
    switch failure {
    case .denied:
        managedSpaceCheckAccessError(.unauthorized, code: "Unauthorized")
    case .unavailable:
        managedSpaceCheckAccessError(.serviceUnavailable, code: "temporarily_unavailable")
    }
}

private func managedSpaceCheckAccessError(
    _ status: HTTPResponse.Status,
    code: String
) -> Response {
    authenticatedGetSpaceJSON(status, ["error": code])
}
