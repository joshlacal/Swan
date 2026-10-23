import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import Petrel
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage

/// The one capability required to expose a user's PDS delegation endpoint.
/// It is built only by ``SwanHTTPServer`` from its fixed DPoP authorizer, a
/// startup-preopened account directory, and a separately configured account
/// key signer.  No route-selected database/key resolver is representable.
public struct SwanSpaceDelegationMintingCapability: Sendable {
    let authorizer: SwanOAuthResourceAuthorizer
    let accounts: any AuthorizedPreopenedAccountDirectory
    let tokenIssuer: any SpaceDelegationTokenIssuer

    init(
        authorizer: SwanOAuthResourceAuthorizer,
        accounts: any AuthorizedPreopenedAccountDirectory,
        tokenIssuer: any SpaceDelegationTokenIssuer
    ) {
        self.authorizer = authorizer
        self.accounts = accounts
        self.tokenIssuer = tokenIssuer
    }
}

private enum SpaceDelegationMintingFailure: Error {
    case invalidRequest
    case denied
    case nonceChallenge
    case unavailable
}

/// The generated server contract keeps the handler's public input/output tied
/// to the checked-in profile.  The HTTP adapter below owns the exact singleton
/// query grammar and opaque error rendering.
private struct AuthenticatedGetSpaceDelegationTokenHandler:
    ComAtprotoSpaceGetDelegationToken.ServerHandler
{
    typealias Context = Request

    let capability: SwanSpaceDelegationMintingCapability

    func handle(
        parameters: ComAtprotoSpaceGetDelegationToken.Parameters,
        input: Void,
        context request: Request
    ) async throws -> ComAtprotoSpaceGetDelegationToken.Output {
        let space: SpaceURI
        do {
            space = try SpaceURI(parameters.space.uriString())
        } catch {
            throw SpaceDelegationMintingFailure.invalidRequest
        }

        let authorization: AuthorizationContext
        do {
            authorization = try await capability.authorizer.authorizeSpaceRoute(
                request: request,
                method: "GET",
                fixedPath: "/xrpc/com.atproto.space.getDelegationToken",
                legacyAdmission: .fullAccessOnly
            )
        } catch let failure as SwanResourceAuthorizationFailure {
            throw switch failure {
            case .nonceChallengeRequired: SpaceDelegationMintingFailure.nonceChallenge
            case .denied: SpaceDelegationMintingFailure.denied
            case .unavailable: SpaceDelegationMintingFailure.unavailable
            }
        } catch {
            throw SpaceDelegationMintingFailure.unavailable
        }

        // The DELEGATION FENCE (§5.6.3, §6.2). `space` is already a validated
        // `SpaceURI` at `:56`, so the three-`String` argument list collapses to
        // one value — removing the argument-order bug the current
        // `spaceType:authority:skey:` signature admits, all three being
        // `String`.
        //
        // A whole-space read grant is what an app EXCHANGES for a credential;
        // it is not itself one (`packages/pds/src/api/com/atproto/space/util.ts:102-108`).
        // Swan's fence is a documented HARDENING of that upstream rule, not an
        // invention: upstream accepts both a bare `space:<type>` and a
        // collection-qualified read here (`getDelegationToken.ts:22`,
        // `space-permission.ts:104-107` and `:207-211`); Swan refuses both.
        //
        // Denial is this route's existing opaque code, identical to a bad token
        // (§6.5.8, §9-D6).
        guard case let .accountOAuth(subject, permissions) = authorization,
              permissions.allowsSpace(.delegationExchange(space)) else {
            throw SpaceDelegationMintingFailure.denied
        }

        do {
            // This validates the user's active lifecycle state and that the
            // exact account database was opened at startup.  It deliberately
            // does not inspect the target authority or its membership policy:
            // only the authority decides those facts during token exchange.
            try await capability.accounts.requireActivePreopenedAccount(subject)
        } catch let error as SwanError {
            switch error {
            case .unavailable:
                throw SpaceDelegationMintingFailure.unavailable
            case .unauthorized, .invalidIdentifier, .invalidProfile,
                    .conflict, .expired, .malformed:
                throw SpaceDelegationMintingFailure.denied
            }
        } catch {
            throw SpaceDelegationMintingFailure.unavailable
        }

        do {
            let token = try await capability.tokenIssuer.issueDelegation(
                space: space,
                issuer: subject,
                now: Date()
            )
            // The token-issuer protocol is intentionally narrow, but an
            // adapter may still be backed by an HSM or another local signing
            // service.  Inspect its bounded output before it reaches HTTP so
            // no implementation can accidentally turn this fixed endpoint
            // into an issuer/audience/algorithm delegation oracle.  Signature
            // verification remains the authority's responsibility; the local
            // AccountKeyStore implementation is covered against the Task6
            // local public-key resolver in integration tests.
            let inspection = try PermissionedDataJWT.inspectDelegationToken(token)
            let duration = inspection.claims.exp.subtractingReportingOverflow(
                inspection.claims.iat
            )
            guard inspection.header.alg == "ES256",
                  inspection.header.kid == PermissionedDataJWT.delegationKeyID,
                  inspection.claims.iss == subject,
                  inspection.claims.aud == "\(space.authority)#atproto_pds",
                  inspection.claims.sub == space.rawValue,
                  !duration.overflow,
                  duration.partialValue == Int64(PermissionedDataJWT.delegationLifetime) else {
                throw SpaceDelegationMintingFailure.unavailable
            }
            return .init(token: token)
        } catch let failure as SpaceDelegationMintingFailure {
            throw failure
        } catch let error as SwanError {
            switch error {
            case .unauthorized, .invalidIdentifier:
                throw SpaceDelegationMintingFailure.denied
            case .unavailable, .invalidProfile, .conflict, .expired, .malformed:
                throw SpaceDelegationMintingFailure.unavailable
            }
        } catch {
            throw SpaceDelegationMintingFailure.unavailable
        }
    }
}

func registerAuthenticatedGetSpaceDelegationTokenEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanSpaceDelegationMintingCapability
) {
    let handler = AuthenticatedGetSpaceDelegationTokenHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.getDelegationToken"
    router.get(path) { request, _ async -> Response in
        let parameters: ComAtprotoSpaceGetDelegationToken.Parameters
        do {
            parameters = try parseAuthenticatedGetSpaceDelegationTokenParameters(request)
        } catch {
            return spaceDelegationMintingError(.badRequest, code: "InvalidRequest")
        }

        do {
            let output = try await handler.handle(
                parameters: parameters,
                input: (),
                context: request
            )
            return authenticatedGetSpaceJSON(
                .ok,
                DelegationTokenWireOutput(token: output.token)
            )
        } catch let failure as SpaceDelegationMintingFailure {
            return spaceDelegationMintingResponse(for: failure, capability: capability)
        } catch {
            return spaceDelegationMintingError(
                .serviceUnavailable,
                code: "temporarily_unavailable"
            )
        }
    }

    for method: HTTPRequest.Method in [
        .head, .post, .put, .patch, .delete, .options, .connect, .trace,
    ] {
        router.on(path, method: method) { _, _ -> Response in
            spaceDelegationMintingError(
                .notFound,
                code: "permissioned_endpoint_unavailable"
            )
        }
    }
}

private func parseAuthenticatedGetSpaceDelegationTokenParameters(
    _ request: Request
) throws -> ComAtprotoSpaceGetDelegationToken.Parameters {
    // A delegation's subject is an exact space URI, so tolerate neither a
    // duplicate parameter nor an unrelated query member.  The raw target
    // fragment guard prevents URI normalization from silently changing the
    // authorization target before it becomes a JWT claim.
    guard !request.uri.string.contains("#"),
          let query = request.uri.query,
          !query.isEmpty,
          query.utf8.count <= 4_096,
          !query.contains("&"),
          let separator = query.firstIndex(of: "=") else {
        throw SpaceDelegationMintingFailure.invalidRequest
    }
    let name = query[..<separator]
    let encodedValue = query[query.index(after: separator)...]
    guard name == "space", !encodedValue.isEmpty else {
        throw SpaceDelegationMintingFailure.invalidRequest
    }

    let rawSpace: String
    do {
        rawSpace = try strictQueryDecode(encodedValue)
        guard rawSpace.utf8.count <= 2_048 else {
            throw SpaceDelegationMintingFailure.invalidRequest
        }
        let uri = try SpaceRef(uriString: rawSpace)
        _ = try SpaceURI(uri.uriString())
        return .init(space: uri)
    } catch {
        throw SpaceDelegationMintingFailure.invalidRequest
    }
}

private struct DelegationTokenWireOutput: Encodable {
    let token: String
}

private func spaceDelegationMintingResponse(
    for failure: SpaceDelegationMintingFailure,
    capability: SwanSpaceDelegationMintingCapability
) -> Response {
    switch failure {
    case .invalidRequest:
        spaceDelegationMintingError(.badRequest, code: "InvalidRequest")
    case .denied:
        spaceDelegationMintingError(.unauthorized, code: "Unauthorized")
    case .nonceChallenge:
        authenticatedGetSpaceNonceChallenge(authorizer: capability.authorizer)
    case .unavailable:
        spaceDelegationMintingError(.serviceUnavailable, code: "temporarily_unavailable")
    }
}

private func spaceDelegationMintingError(
    _ status: HTTPResponse.Status,
    code: String
) -> Response {
    authenticatedGetSpaceJSON(status, ["error": code])
}
