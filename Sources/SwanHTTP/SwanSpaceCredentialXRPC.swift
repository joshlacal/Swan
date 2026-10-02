import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import Petrel
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage

/// The request-only capability for an authority's delegation exchange. It is
/// assembled by ``SwanHTTPServer`` from a startup-preopened credential-policy
/// directory and explicitly local/pinned key resolvers. Neither the HTTP
/// route nor the capability has a database handle, remote resolver, or raw
/// signing material.
public struct SwanSpaceCredentialExchangeCapability: Sendable {
    let authorizer: SwanOAuthResourceAuthorizer
    let delegationAuthorizer: any SpaceDelegationAuthorizationVerifier
    /// The runtime's dedicated HMAC-backed replay store. A delegation is
    /// reserved after its signature is verified but before policy evaluation
    /// or credential signing, so a concurrent/reopened authority cannot mint
    /// two credentials from one JTI.
    let delegationReplayStore: DurableSpaceDelegationReplayStore
    let credentialIssuer: any SpaceCredentialAuthoritySigner

    init(
        authorizer: SwanOAuthResourceAuthorizer,
        delegationAuthorizer: any SpaceDelegationAuthorizationVerifier,
        delegationReplayStore: DurableSpaceDelegationReplayStore,
        credentialIssuer: any SpaceCredentialAuthoritySigner
    ) {
        self.authorizer = authorizer
        self.delegationAuthorizer = delegationAuthorizer
        self.delegationReplayStore = delegationReplayStore
        self.credentialIssuer = credentialIssuer
    }
}

enum SwanSpaceCredentialHTTP {
    /// Exchange bodies contain only a space URI and (optionally) a compact
    /// client attestation. Keep this much smaller than record-write JSON so a
    /// procedure that returns a bound credential cannot become a generic
    /// buffered upload endpoint.
    static let maximumJSONBytes = 16 * 1_024
}

private enum SpaceCredentialExchangeFailure: Error {
    case invalidRequest
    case invalidDelegation
    /// `BadSpaceSignature`: the exchange's `atproto-space` HTTP message
    /// signature is missing, malformed, or does not verify under its keyid.
    case invalidSignature
    case invalidClientAttestation
    case spaceNotFound
    case spaceDeleted
    case appNotAuthorized
    case notAuthorized
    case unavailable
}

private struct AuthenticatedGetSpaceCredentialHandler:
    ComAtprotoSpaceGetSpaceCredential.ServerHandler
{
    typealias Context = Request

    let capability: SwanSpaceCredentialExchangeCapability

    func handle(
        parameters: Void,
        input: ComAtprotoSpaceGetSpaceCredential.Input,
        context request: Request
    ) async throws -> ComAtprotoSpaceGetSpaceCredential.Output {
        let space: SpaceURI
        do {
            space = try SpaceURI(input.space.uriString())
        } catch {
            throw SpaceCredentialExchangeFailure.invalidRequest
        }

        let delegation: String
        do {
            guard let token = try exactBearerToken(from: request.headers) else {
                throw SpaceCredentialExchangeFailure.invalidDelegation
            }
            delegation = token
        } catch let failure as SpaceCredentialExchangeFailure {
            throw failure
        } catch {
            throw SpaceCredentialExchangeFailure.invalidDelegation
        }

        let delegationGrant: VerifiedSpaceDelegation
        do {
            delegationGrant = try await capability.delegationAuthorizer.verifiedDelegation(
                for: delegation,
                expectedSpace: space,
                now: Date()
            )
        } catch {
            // The public exchange surface never distinguishes an unknown
            // issuer/pin/key from malformed, expired, wrong-audience, or bad
            // signature delegation material. None of these paths may enter a
            // durable policy transaction or invoke the signing resolver.
            throw SpaceCredentialExchangeFailure.invalidDelegation
        }
        guard case let .spaceDelegation(user, delegatedSpace) = delegationGrant.authorization,
              delegatedSpace == space,
              delegationGrant.issuer == user,
              delegationGrant.space == space else {
            throw SpaceCredentialExchangeFailure.invalidDelegation
        }

        // atproto#5569: the client proves possession of a fresh P-256 key by
        // signing exactly ("authorization") and naming the key as `keyid`.
        // That key becomes the credential's `cnf.kid`. There is no method,
        // URL, nonce, or per-request replay binding to check any more; the
        // delegation's own single-use reservation below is what stops reuse.
        let confirmationKeyID: String
        do {
            confirmationKeyID = try capability.authorizer.verifySpaceDelegationSignature(
                request: request
            )
        } catch {
            throw SpaceCredentialExchangeFailure.invalidSignature
        }

        // Proposal 0016 delegations are single-use. Reserve the verified
        // opaque JTI before attestation/policy/signing so a duplicate request
        // cannot create another credential, and so the authority never
        // evaluates policy or decrypts a signing key for a rejected replay.
        let replayNow = Date()
        do {
            let replayExpiry = delegationGrant.expiresAt.addingTimeInterval(60)
            guard try await capability.delegationReplayStore.claim(
                issuer: delegationGrant.issuer,
                audience: delegationGrant.audience,
                space: delegationGrant.space,
                jti: delegationGrant.jti,
                expiresAt: replayExpiry,
                now: replayNow
            ) else {
                throw SpaceCredentialExchangeFailure.invalidDelegation
            }
        } catch let failure as SpaceCredentialExchangeFailure {
            throw failure
        } catch {
            // Retain the same opaque delegation error for a duplicate or an
            // unavailable replay store; the exchange must not continue into
            // durable policy/signing without its single-use reservation.
            throw SpaceCredentialExchangeFailure.invalidDelegation
        }

        do {
            let credential = try await capability.credentialIssuer.issueSpaceCredential(
                space: space,
                user: user,
                authorization: delegationGrant.authorization,
                clientAttestation: input.clientAttestation,
                confirmationKeyID: confirmationKeyID,
                now: Date()
            )
            return .init(credential: credential)
        } catch let failure as SpaceCredentialClientAttestationFailure {
            switch failure {
            case .invalid:
                throw SpaceCredentialExchangeFailure.invalidClientAttestation
            case .unavailable:
                throw SpaceCredentialExchangeFailure.unavailable
            }
        } catch let failure as AuthorizedSimpleSpaceLifecycleError {
            throw failure == .deleted
                ? SpaceCredentialExchangeFailure.spaceDeleted
                : SpaceCredentialExchangeFailure.spaceNotFound
        } catch is SimpleSpaceCredentialPolicyError {
            throw SpaceCredentialExchangeFailure.appNotAuthorized
        } catch let error as SwanError {
            switch error {
            case .unavailable:
                throw SpaceCredentialExchangeFailure.unavailable
            case .unauthorized:
                throw SpaceCredentialExchangeFailure.notAuthorized
            case .invalidIdentifier, .invalidProfile, .conflict, .expired, .malformed:
                throw SpaceCredentialExchangeFailure.invalidRequest
            }
        } catch {
            throw SpaceCredentialExchangeFailure.unavailable
        }
    }
}

func registerAuthenticatedGetSpaceCredentialEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanSpaceCredentialExchangeCapability,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) {
    let handler = AuthenticatedGetSpaceCredentialHandler(capability: capability)
    let path: RouterPath = "/xrpc/com.atproto.space.getSpaceCredential"
    router.post(path) { request, context async -> Response in
        do {
            let input = try await decodeGetSpaceCredentialInput(
                request,
                context: context,
                requestBodyAdmission: requestBodyAdmission
            )
            let output = try await handler.handle(
                parameters: (), input: input, context: request
            )
            return authenticatedGetSpaceJSON(
                .ok,
                GetSpaceCredentialWireOutput(credential: output.credential)
            )
        } catch let failure as SpaceCredentialExchangeFailure {
            return getSpaceCredentialResponse(for: failure)
        } catch let failure as SwanRequestBodyCollectionFailure {
            return getSpaceCredentialResponse(
                for: failure == .unavailable ? .unavailable : .invalidRequest
            )
        } catch {
            return getSpaceCredentialError(.badRequest, code: "InvalidRequest")
        }
    }
    for method: HTTPRequest.Method in [
        .get, .head, .put, .patch, .delete, .options, .connect, .trace,
    ] {
        router.on(path, method: method) { _, _ -> Response in
            getSpaceCredentialError(
                .notFound,
                code: "permissioned_endpoint_unavailable"
            )
        }
    }
}

private func decodeGetSpaceCredentialInput(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws -> ComAtprotoSpaceGetSpaceCredential.Input {
    let body = try await collectAdmittedRequestBody(
        request,
        mediaType: .json,
        admission: requestBodyAdmission.admission,
        policy: requestBodyAdmission.policy,
        maximumBytes: SwanSpaceCredentialHTTP.maximumJSONBytes,
        termination: context.jsonWriteBodyTermination
    )
    defer { withExtendedLifetime(body) {} }
    guard body.readableBytes > 0,
          let bytes = body.getBytes(
              at: body.readerIndex,
              length: body.readableBytes
          ) else {
        throw SpaceCredentialExchangeFailure.invalidRequest
    }
    let data = Data(bytes)
    do {
        // Reuse the existing recursive duplicate-member validator before
        // Foundation decodes the same exact bytes into the generated input.
        try StrictPermissionedWriteJSON.validate(data)
    } catch {
        throw SpaceCredentialExchangeFailure.invalidRequest
    }
    guard let root = try? JSONSerialization.jsonObject(with: data)
        as? [String: Any],
        !root.isEmpty,
        Set(root.keys).isSubset(of: ["space", "clientAttestation"]),
        root.keys.filter({ $0 == "space" }).count == 1,
        let rawSpace = root["space"] as? String,
        !rawSpace.isEmpty,
        rawSpace.utf8.count <= 2_048 else {
        throw SpaceCredentialExchangeFailure.invalidRequest
    }
    if let attestation = root["clientAttestation"] {
        guard let text = attestation as? String,
              !text.isEmpty,
              text.utf8.count <= PermissionedDataJWT.maximumCompactDelegationBytes else {
            throw SpaceCredentialExchangeFailure.invalidRequest
        }
    }
    do {
        let input = try JSONDecoder().decode(
            ComAtprotoSpaceGetSpaceCredential.Input.self,
            from: data
        )
        _ = try SpaceURI(input.space.uriString())
        return input
    } catch {
        throw SpaceCredentialExchangeFailure.invalidRequest
    }
}

/// Returns a compact Bearer value only when the request has exactly one
/// authorization field whose scheme is Bearer (case-insensitive per HTTP).
/// `nil` means another scheme and lets the caller use its own policy; a
/// malformed Bearer field is an error and must not fall through to a
/// different authentication scheme.
func exactBearerToken(from headers: HTTPFields) throws -> String? {
    let values = headers[values: .authorization]
    guard values.count <= 1 else {
        throw SpaceCredentialExchangeFailure.invalidDelegation
    }
    guard let raw = values.first else { return nil }
    let bearerPrefix = "Bearer "
    if raw.count >= bearerPrefix.count,
       raw.prefix(bearerPrefix.count)
        .caseInsensitiveCompare(bearerPrefix) == .orderedSame {
        let token = String(raw.dropFirst(bearerPrefix.count))
        guard !token.isEmpty,
              token.utf8.count <= PermissionedDataJWT.maximumCompactDelegationBytes,
              token.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw SpaceCredentialExchangeFailure.invalidDelegation
        }
        return token
    }
    // HTTP authorization schemes are case-insensitive. If this field tried
    // to use Bearer with an invalid separator/casing, fail it rather than
    // treating it as a DPoP or future scheme.
    if raw.lowercased().hasPrefix("bearer") {
        throw SpaceCredentialExchangeFailure.invalidDelegation
    }
    return nil
}

/// The authorization scheme a space credential is presented under
/// (atproto#5569), compared case-insensitively.
let spaceCredentialAuthorizationScheme = "Atproto-Space"

/// A compact space credential presented as `Authorization: Atproto-Space
/// <credential>`, or `nil` when the request uses another scheme so the caller
/// falls through to its OAuth policy unchanged.
///
/// Throws (an opaque denial) when the presentation is unusable as either:
/// a duplicated `Authorization` field naming this scheme, a malformed
/// credential value, or a credential JWT smuggled under `Bearer` or `DPoP`
/// (the pre-#5569 DPoP-bound presentation). The `typ` peek only routes; the
/// verifier makes every security decision.
func spaceCredentialSchemeToken(from headers: HTTPFields) throws -> String? {
    let values = headers[values: .authorization]
    let prefix = spaceCredentialAuthorizationScheme + " "
    let isSpaceScheme: (String) -> Bool = { raw in
        raw.count >= prefix.count
            && raw.prefix(prefix.count).caseInsensitiveCompare(prefix) == .orderedSame
    }
    if values.contains(where: isSpaceScheme) {
        guard values.count == 1 else {
            throw SpaceCredentialPresentationFailure.badSignature
        }
        let token = String(values[0].dropFirst(prefix.count))
        guard !token.isEmpty,
              token.utf8.count <= PermissionedDataJWT.maximumCompactSpaceCredentialBytes,
              token.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw SpaceCredentialPresentationFailure.badSignature
        }
        return token
    }
    if let bearer = try exactBearerToken(from: headers) {
        guard unverifiedCompactJOSEType(of: bearer) != PermissionedDataJWT.credentialType else {
            throw SwanError.unauthorized("space credential presented under the wrong scheme")
        }
        return nil
    }
    let dpopPrefix = "DPoP "
    if let raw = values.first,
       raw.count >= dpopPrefix.count,
       raw.prefix(dpopPrefix.count).caseInsensitiveCompare(dpopPrefix) == .orderedSame,
       unverifiedCompactJOSEType(of: String(raw.dropFirst(dpopPrefix.count)))
        == PermissionedDataJWT.credentialType {
        throw SwanError.unauthorized("space credential presented under the wrong scheme")
    }
    return nil
}

/// The JOSE header `typ` of a compact token, decoded WITHOUT verification —
/// usable only to route a presentation, never to trust one.
private func unverifiedCompactJOSEType(of compact: String) -> String? {
    guard let first = compact.split(separator: ".").first,
          let data = Data(base64URLEncoded: String(first)),
          data.count <= 4_096,
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        return nil
    }
    return object["typ"] as? String
}

private struct GetSpaceCredentialWireOutput: Encodable {
    let credential: String
}

private func getSpaceCredentialResponse(
    for failure: SpaceCredentialExchangeFailure
) -> Response {
    switch failure {
    case .invalidRequest:
        getSpaceCredentialError(.badRequest, code: "InvalidRequest")
    case .invalidDelegation:
        getSpaceCredentialError(.unauthorized, code: "InvalidDelegationToken")
    case .invalidSignature:
        getSpaceCredentialError(.unauthorized, code: "BadSpaceSignature")
    case .invalidClientAttestation:
        getSpaceCredentialError(.badRequest, code: "InvalidClientAttestation")
    case .spaceNotFound:
        getSpaceCredentialError(.notFound, code: "SpaceNotFound")
    case .spaceDeleted:
        getSpaceCredentialError(.badRequest, code: "SpaceDeleted")
    case .appNotAuthorized:
        getSpaceCredentialError(.unauthorized, code: "AppNotAuthorized")
    case .notAuthorized:
        getSpaceCredentialError(.unauthorized, code: "NotAuthorized")
    case .unavailable:
        getSpaceCredentialError(.serviceUnavailable, code: "temporarily_unavailable")
    }
}

private func getSpaceCredentialError(
    _ status: HTTPResponse.Status,
    code: String
) -> Response {
    authenticatedGetSpaceJSON(status, ["error": code])
}
