import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import Petrel
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage

/// The request-only capability for an authority's sync authorization
/// exchange. Registration state is selected from the same startup-preopened
/// authority database as policy; the confirmer is the only network
/// capability and applies Swan's untrusted-fetch policy.
public struct SwanSpaceCredentialExchangeCapability: Sendable {
    let authorizer: SwanOAuthResourceAuthorizer
    let delegationAuthorizer: any SpaceDelegationAuthorizationVerifier
    let delegationReplayStore: DurableSpaceDelegationReplayStore
    let credentialIssuer: any SpaceCredentialAuthoritySigner
    let registrationDirectory: any AuthorizedSpaceSyncRegistrationDirectory
    let registrationConfirmer: (any SwanSpaceRegistrationConfirming)?
    let allowLocalhostNotificationEndpoints: Bool

    init(
        authorizer: SwanOAuthResourceAuthorizer,
        delegationAuthorizer: any SpaceDelegationAuthorizationVerifier,
        delegationReplayStore: DurableSpaceDelegationReplayStore,
        credentialIssuer: any SpaceCredentialAuthoritySigner,
        registrationDirectory: any AuthorizedSpaceSyncRegistrationDirectory,
        registrationConfirmer: (any SwanSpaceRegistrationConfirming)? = nil,
        allowLocalhostNotificationEndpoints: Bool = false
    ) {
        self.authorizer = authorizer
        self.delegationAuthorizer = delegationAuthorizer
        self.delegationReplayStore = delegationReplayStore
        self.credentialIssuer = credentialIssuer
        self.registrationDirectory = registrationDirectory
        self.registrationConfirmer = registrationConfirmer
        self.allowLocalhostNotificationEndpoints =
            allowLocalhostNotificationEndpoints
    }
}

enum SwanSpaceCredentialHTTP {
    static let maximumJSONBytes = 16 * 1_024
}

private enum SpaceCredentialExchangeFailure: Error {
    case invalidRequest
    case invalidDelegation
    case invalidSignature
    case invalidClientAttestation
    case spaceNotFound
    case spaceDeleted
    case appNotAuthorized
    case notAuthorized
    case registrationNotConfirmed
    case repoTakendown
    case repoDeactivated
    case upstreamFailure
    case unavailable
}

private struct AuthorizeSpaceSyncInput: Decodable {
    struct Notification: Decodable {
        let endpoint: String
        let token: String
    }

    let space: String
    let credentialKey: String
    let delegationToken: String?
    let clientAttestation: String?
    let notify: Notification?
}

private struct AuthorizeSpaceSyncOutput: Encodable {
    let credential: String
    let spaceRev: String?
}

private struct AuthenticatedAuthorizeSpaceSyncHandler {
    let capability: SwanSpaceCredentialExchangeCapability

    func handle(
        input: AuthorizeSpaceSyncInput
    ) async throws -> AuthorizeSpaceSyncOutput {
        let space: SpaceURI
        do {
            space = try SpaceURI(input.space)
        } catch {
            throw SpaceCredentialExchangeFailure.invalidRequest
        }
        guard PermissionedDataJWT.isValidConfirmationKeyID(input.credentialKey) else {
            throw SpaceCredentialExchangeFailure.invalidRequest
        }
        let notify = try input.notify.map {
            value -> (endpoint: URL, rawEndpoint: String, token: String) in
            guard let endpoint = validNotificationEndpoint(
                value.endpoint,
                allowLocalhostDevelopment:
                    capability.allowLocalhostNotificationEndpoints
            ),
                  !value.token.isEmpty,
                  value.token.utf8.count <= 512 else {
                throw SpaceCredentialExchangeFailure.invalidRequest
            }
            return (endpoint, value.endpoint, value.token)
        }

        // Only a durable tombstone is disclosed before delegation validation.
        // Absence falls through so it is indistinguishable from an existing
        // private space to an unauthenticated caller.
        do {
            _ = try await capability.registrationDirectory.activeSpaceRevision(space)
        } catch AuthorizedSimpleSpaceLifecycleError.notFound {
        } catch AuthorizedSimpleSpaceLifecycleError.deleted {
            throw SpaceCredentialExchangeFailure.spaceDeleted
        } catch {
            throw spaceCredentialExchangeFailure(for: error)
        }

        var user: String?
        var authorization: AuthorizationContext = .public
        if let delegation = input.delegationToken {
            do {
                let grant = try await capability.delegationAuthorizer.verifiedDelegation(
                    for: delegation,
                    expectedSpace: space,
                    now: Date()
                )
                guard case let .spaceDelegation(subject, delegatedSpace) = grant.authorization,
                      delegatedSpace == space,
                      grant.issuer == subject,
                      grant.space == space,
                      try await capability.delegationReplayStore.claim(
                        issuer: grant.issuer,
                        audience: grant.audience,
                        space: grant.space,
                        jti: grant.jti,
                        expiresAt: grant.expiresAt.addingTimeInterval(60),
                        now: Date()
                      ) else {
                    throw SpaceCredentialExchangeFailure.invalidDelegation
                }
                user = subject
                authorization = grant.authorization
            } catch {
                throw SpaceCredentialExchangeFailure.invalidDelegation
            }
        }

        let credential: String
        do {
            credential = try await capability.credentialIssuer.issueSpaceCredential(
                space: space,
                user: user,
                authorization: authorization,
                clientAttestation: input.clientAttestation,
                confirmationKeyID: input.credentialKey,
                now: Date()
            )
        } catch {
            if let notify, isSpaceSyncAuthorizationDenial(error) {
                do {
                    try await capability.registrationDirectory.removeSpaceSyncRegistration(
                        space: space,
                        endpoint: notify.rawEndpoint,
                        token: notify.token
                    )
                } catch {
                    throw spaceCredentialExchangeFailure(for: error)
                }
            }
            throw spaceCredentialExchangeFailure(for: error)
        }

        if let notify {
            let endpoint = notify.rawEndpoint
            let existing: AuthorizedSpaceSyncRegistration?
            do {
                existing = try await capability.registrationDirectory.spaceSyncRegistration(
                    space: space,
                    endpoint: endpoint,
                    token: notify.token
                )
            } catch {
                throw spaceCredentialExchangeFailure(for: error)
            }
            if existing == nil {
                guard let confirmer = capability.registrationConfirmer else {
                    throw SpaceCredentialExchangeFailure.registrationNotConfirmed
                }
                do {
                    try await confirmer.confirmRegistration(
                        space: space,
                        endpoint: notify.endpoint,
                        token: notify.token,
                        challenge: UUID().uuidString.lowercased()
                    )
                } catch {
                    throw SpaceCredentialExchangeFailure.registrationNotConfirmed
                }
            }
            let expiresAt: Date
            do {
                let inspection = try PermissionedDataJWT.inspectSpaceCredential(credential)
                expiresAt = Date(
                    timeIntervalSince1970: TimeInterval(inspection.claims.exp)
                )
            } catch {
                throw SpaceCredentialExchangeFailure.unavailable
            }
            do {
                try await capability.registrationDirectory.putSpaceSyncRegistration(
                    AuthorizedSpaceSyncRegistration(
                        space: space,
                        endpoint: endpoint,
                        token: notify.token,
                        expiresAt: expiresAt
                    ),
                    allowLocalhostDevelopment:
                        capability.allowLocalhostNotificationEndpoints
                )
            } catch {
                throw spaceCredentialExchangeFailure(for: error)
            }
        }

        do {
            return AuthorizeSpaceSyncOutput(
                credential: credential,
                spaceRev: try await capability.registrationDirectory.activeSpaceRevision(space)
            )
        } catch {
            throw spaceCredentialExchangeFailure(for: error)
        }
    }
}

func registerAuthenticatedAuthorizeSpaceSyncEndpoint(
    on router: Router<BasicRequestContext>,
    capability: SwanSpaceCredentialExchangeCapability,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) {
    let handler = AuthenticatedAuthorizeSpaceSyncHandler(capability: capability)
    let path = RouterPath("/xrpc/\(ComAtprotoSpaceAuthorizeSpaceSync.typeIdentifier)")
    router.post(path) { request, context async -> Response in
        do {
            let input = try await decodeAuthorizeSpaceSyncInput(
                request,
                context: context,
                requestBodyAdmission: requestBodyAdmission,
                allowLocalhostNotificationEndpoints:
                    capability.allowLocalhostNotificationEndpoints
            )
            return authenticatedGetSpaceJSON(
                .ok,
                try await handler.handle(input: input)
            )
        } catch let failure as SpaceCredentialExchangeFailure {
            return authorizeSpaceSyncResponse(for: failure)
        } catch let failure as SwanRequestBodyCollectionFailure {
            return authorizeSpaceSyncResponse(
                for: failure == .unavailable ? .unavailable : .invalidRequest
            )
        } catch {
            return authorizeSpaceSyncError(.badRequest, code: "InvalidRequest")
        }
    }
    for method: HTTPRequest.Method in [
        .get, .head, .put, .patch, .delete, .options, .connect, .trace,
    ] {
        router.on(path, method: method) { _, _ -> Response in
            authorizeSpaceSyncError(
                .notFound,
                code: "permissioned_endpoint_unavailable"
            )
        }
    }
}

private func decodeAuthorizeSpaceSyncInput(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration,
    allowLocalhostNotificationEndpoints: Bool
) async throws -> AuthorizeSpaceSyncInput {
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
        try StrictPermissionedWriteJSON.validate(data)
    } catch {
        throw SpaceCredentialExchangeFailure.invalidRequest
    }
    guard let root = try? JSONSerialization.jsonObject(with: data)
            as? [String: Any],
          Set(root.keys).isSubset(
            of: [
                "space", "credentialKey", "delegationToken",
                "clientAttestation", "notify",
            ]
          ),
          let rawSpace = root["space"] as? String,
          !rawSpace.isEmpty,
          rawSpace.utf8.count <= 2_048,
          let credentialKey = root["credentialKey"] as? String,
          PermissionedDataJWT.isValidConfirmationKeyID(credentialKey) else {
        throw SpaceCredentialExchangeFailure.invalidRequest
    }
    for field in ["clientAttestation", "delegationToken"] where root[field] != nil {
        guard let text = root[field] as? String,
              !text.isEmpty,
              text.utf8.count <= PermissionedDataJWT.maximumCompactDelegationBytes else {
            throw SpaceCredentialExchangeFailure.invalidRequest
        }
    }
    if let rawNotify = root["notify"] {
        guard let notification = rawNotify as? [String: Any],
              let endpoint = notification["endpoint"] as? String,
              validNotificationEndpoint(
                endpoint,
                allowLocalhostDevelopment:
                    allowLocalhostNotificationEndpoints
              ) != nil,
              let token = notification["token"] as? String,
              !token.isEmpty,
              token.utf8.count <= 512 else {
            throw SpaceCredentialExchangeFailure.invalidRequest
        }
    }
    do {
        let input = try JSONDecoder().decode(AuthorizeSpaceSyncInput.self, from: data)
        _ = try SpaceURI(input.space)
        return input
    } catch {
        throw SpaceCredentialExchangeFailure.invalidRequest
    }
}


private func isSpaceSyncAuthorizationDenial(_ error: Error) -> Bool {
    if let lifecycle = error as? AuthorizedSimpleSpaceLifecycleError {
        return lifecycle == .notFound
    }
    if error is SimpleSpaceCredentialPolicyError { return true }
    if case .unauthorized = error as? SwanError { return true }
    return false
}

private func spaceCredentialExchangeFailure(
    for error: Error
) -> SpaceCredentialExchangeFailure {
    if error is any AuthorizedSpaceUpstreamFailure {
        return .upstreamFailure
    }
    if let status = error as? AuthorizedSpaceAuthorityStatusError {
        return status == .takendown ? .repoTakendown : .repoDeactivated
    }
    if let failure = error as? SpaceCredentialClientAttestationFailure {
        return failure == .invalid ? .invalidClientAttestation : .unavailable
    }
    if let lifecycle = error as? AuthorizedSimpleSpaceLifecycleError {
        return lifecycle == .deleted ? .spaceDeleted : .spaceNotFound
    }
    if error is SimpleSpaceCredentialPolicyError {
        return .appNotAuthorized
    }
    if let error = error as? SwanError {
        switch error {
        case .unavailable:
            return .unavailable
        case .unauthorized:
            return .notAuthorized
        case .invalidIdentifier, .invalidProfile, .conflict, .expired, .malformed:
            return .invalidRequest
        }
    }
    return .unavailable
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
let spaceCredentialAuthorizationScheme = "Atproto-Space-Credential"

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
    if values.contains(where: { $0.lowercased().hasPrefix("atproto-space ") }) {
        throw SpaceCredentialPresentationFailure.unsupportedAuthorization
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


private func authorizeSpaceSyncResponse(
    for failure: SpaceCredentialExchangeFailure
) -> Response {
    switch failure {
    case .invalidRequest:
        authorizeSpaceSyncError(.badRequest, code: "InvalidRequest")
    case .invalidDelegation:
        authorizeSpaceSyncError(.badRequest, code: "InvalidDelegationToken")
    case .invalidSignature:
        authorizeSpaceSyncError(.unauthorized, code: "BadSpaceSignature")
    case .invalidClientAttestation:
        authorizeSpaceSyncError(.badRequest, code: "InvalidClientAttestation")
    case .spaceNotFound:
        authorizeSpaceSyncError(.badRequest, code: "SpaceNotFound")
    case .spaceDeleted:
        authorizeSpaceSyncError(.badRequest, code: "SpaceDeleted")
    case .appNotAuthorized:
        authorizeSpaceSyncError(.badRequest, code: "AppNotAuthorized")
    case .notAuthorized:
        authorizeSpaceSyncError(.badRequest, code: "NotAuthorized")
    case .registrationNotConfirmed:
        authorizeSpaceSyncError(.badRequest, code: "RegistrationNotConfirmed")
    case .repoTakendown:
        authorizeSpaceSyncError(.badRequest, code: "RepoTakendown")
    case .repoDeactivated:
        authorizeSpaceSyncError(.badRequest, code: "RepoDeactivated")
    case .upstreamFailure:
        authorizeSpaceSyncError(.badGateway, code: "UpstreamFailure")
    case .unavailable:
        authorizeSpaceSyncError(.serviceUnavailable, code: "temporarily_unavailable")
    }
}

private func authorizeSpaceSyncError(
    _ status: HTTPResponse.Status,
    code: String
) -> Response {
    authenticatedGetSpaceJSON(status, ["error": code])
}
