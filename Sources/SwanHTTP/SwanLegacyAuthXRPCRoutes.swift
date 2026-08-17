import Foundation
import HTTPTypes
import Hummingbird
import NIOCore
import Petrel
import SwanAccounts
import SwanCore
import SwanOAuth

/// Registration for the pinned `com.atproto.server` legacy-auth XRPC methods.
///
/// The integration owner installs these exact routes before the unknown-public
/// guards and the `/xrpc/**` proxy fallback so a legacy credential never
/// leaves this host. Management cookies never authenticate XRPC: the five
/// bearer-authenticated methods use `SwanLegacyBearerAuthorizer`, and the
/// three app-password methods require a `LegacyXRPCAuthorizationContext`
/// (authenticated management session + fresh step-up receipt) that XRPC
/// cannot carry, so they fail closed with a stable 403 rather than weakening
/// app-password management to a bare bearer.
func registerSwanLegacyAuthXRPC(
    on router: Router<SwanHTTPRequestContext>,
    adapter: SwanLegacyAuthXRPCAdapter,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) {
    // com.atproto.server.createSession — password or app-password login.
    router.post("/xrpc/com.atproto.server.createSession") { request, context async -> Response in
        do {
            let input: ComAtprotoServerCreateSession.Input = try await decodeLegacyExactJSON(
                request,
                context: context,
                requestBodyAdmission: requestBodyAdmission,
                required: ["identifier", "password"],
                optional: ["authFactorToken", "allowTakendown"]
            )
            return jsonResponseWithStatus(.ok, body: try await adapter.createSession(input))
        } catch {
            return legacyAuthErrorResponse(for: error)
        }
    }

    // com.atproto.server.refreshSession — bodyless; the refresh JWT travels
    // in `Authorization: Bearer ...` exactly as the generated client sends it
    // (the lexicon declares no input schema). The same RFC 9110 bearer
    // extraction the other bearer methods use validates the credential; a
    // JSON body is not accepted here.
    router.post("/xrpc/com.atproto.server.refreshSession") { request, context async -> Response in
        do {
            let token = try SwanLegacyBearerAuthorizer.accessToken(from: request.headers)
            try await requireLegacyEmptyBody(
                request,
                context: context,
                requestBodyAdmission: requestBodyAdmission
            )
            return jsonResponseWithStatus(
                .ok,
                body: try await adapter.refreshSession(refreshToken: token)
            )
        } catch {
            return legacyAuthErrorResponse(for: error)
        }
    }

    // com.atproto.server.getSession — bearer access token, no body.
    router.get("/xrpc/com.atproto.server.getSession") { request, _ async -> Response in
        do {
            let token = try SwanLegacyBearerAuthorizer.accessToken(from: request.headers)
            return jsonResponseWithStatus(.ok, body: try await adapter.getSession(accessToken: token))
        } catch {
            return legacyAuthErrorResponse(for: error)
        }
    }

    // com.atproto.server.deleteSession — bearer access token, empty body.
    router.post("/xrpc/com.atproto.server.deleteSession") { request, context async -> Response in
        do {
            let token = try SwanLegacyBearerAuthorizer.accessToken(from: request.headers)
            try await requireLegacyEmptyBody(
                request,
                context: context,
                requestBodyAdmission: requestBodyAdmission
            )
            try await adapter.deleteSession(accessToken: token)
            return Response(status: .ok, headers: [.cacheControl: "no-store"])
        } catch {
            return legacyAuthErrorResponse(for: error)
        }
    }

    // com.atproto.server.getServiceAuth — bearer access token, query parameters.
    router.get("/xrpc/com.atproto.server.getServiceAuth") { request, _ async -> Response in
        do {
            let token = try SwanLegacyBearerAuthorizer.accessToken(from: request.headers)
            let parameters = try legacyServiceAuthParameters(from: request.uri.query)
            return jsonResponseWithStatus(
                .ok,
                body: try await adapter.getServiceAuth(accessToken: token, parameters: parameters)
            )
        } catch {
            return legacyAuthErrorResponse(for: error)
        }
    }

    // The three app-password methods require a LegacyXRPCAuthorizationContext
    // (authenticated management session + fresh step-up receipt). XRPC never
    // accepts management cookies, so no request can construct that context
    // here; the routes fail closed with a stable 403 instead of falling back
    // to a bare bearer or the proxy.
    for path in [
        "/xrpc/com.atproto.server.createAppPassword",
        "/xrpc/com.atproto.server.listAppPasswords",
        "/xrpc/com.atproto.server.revokeAppPassword",
    ] {
        let routePath = RouterPath(path)
        router.on(routePath, method: .post) { _, _ async -> Response in
            jsonResponseWithStatus(.forbidden, body: ["error": "request_not_allowed"])
        }
        router.on(routePath, method: .get) { _, _ async -> Response in
            jsonResponseWithStatus(.forbidden, body: ["error": "request_not_allowed"])
        }
    }
}

/// Parses the `getServiceAuth` query parameters under the same strictness the
/// generated client emits: `aud` required, `lxm` and `exp` optional.
private func legacyServiceAuthParameters(from query: String?) throws -> ComAtprotoServerGetServiceAuth.Parameters {
    guard let query, !query.isEmpty,
          let components = URLComponents(string: "https://swan.invalid/?\(query)"),
          let items = components.queryItems else {
        throw SwanError.unauthorized("invalid service auth parameters")
    }
    var aud: String?
    var exp: Int?
    var lxm: NSID?
    for item in items {
        switch item.name {
        case "aud":
            guard aud == nil, let value = item.value, !value.isEmpty else {
                throw SwanError.unauthorized("invalid service auth parameters")
            }
            aud = value
        case "exp":
            guard exp == nil, let value = item.value, let parsed = Int(value), parsed >= 0 else {
                throw SwanError.unauthorized("invalid service auth parameters")
            }
            exp = parsed
        case "lxm":
            guard lxm == nil, let value = item.value, let nsid = try? NSID(nsidString: value) else {
                throw SwanError.unauthorized("invalid service auth parameters")
            }
            lxm = nsid
        default:
            throw SwanError.unauthorized("invalid service auth parameters")
        }
    }
    guard let aud else { throw SwanError.unauthorized("invalid service auth parameters") }
    return ComAtprotoServerGetServiceAuth.Parameters(aud: aud, exp: exp, lxm: lxm)
}

/// Strict JSON admission for the legacy XRPC bodies: exact key set, no null
/// values, bounded bytes, duplicate-key rejection via `StrictJSON`.
private func decodeLegacyExactJSON<Value: Decodable>(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration,
    required: Set<String>,
    optional: Set<String>
) async throws -> Value {
    let buffer: SwanAdmittedRequestBody
    do {
        buffer = try await collectAdmittedRequestBody(
            request,
            mediaType: .json,
            admission: requestBodyAdmission.admission,
            policy: requestBodyAdmission.policy,
            maximumBytes: 8 * 1024,
            termination: context.jsonWriteBodyTermination
        )
    } catch {
        throw SwanError.unauthorized("invalid legacy auth body")
    }
    defer { withExtendedLifetime(buffer) {} }
    guard buffer.readableBytes > 0,
          let bytes = buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes) else {
        throw SwanError.unauthorized("invalid legacy auth body")
    }
    let data = Data(bytes)
    do {
        try StrictJSON.validate(data)
        guard let object = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
            throw SwanError.unauthorized("invalid legacy auth body")
        }
        let keys = Set(object.keys)
        guard required.isSubset(of: keys),
              keys.isSubset(of: required.union(optional)),
              !object.values.contains(where: { $0 is NSNull }) else {
            throw SwanError.unauthorized("invalid legacy auth body")
        }
        return try JSONDecoder().decode(Value.self, from: data)
    } catch let error as SwanError {
        throw error
    } catch {
        throw SwanError.unauthorized("invalid legacy auth body")
    }
}

private func requireLegacyEmptyBody(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws {
    do {
        let body = try await collectAdmittedRequestBody(
            request,
            mediaType: .unspecified,
            admission: requestBodyAdmission.admission,
            policy: requestBodyAdmission.policy,
            maximumBytes: 1,
            termination: context.jsonWriteBodyTermination
        )
        defer { withExtendedLifetime(body) {} }
        guard body.readableBytes == 0 else {
            throw SwanError.unauthorized("invalid legacy auth body")
        }
    } catch let failure as SwanRequestBodyCollectionFailure {
        if failure == .unavailable {
            throw SwanError.unavailable("legacy auth body admission unavailable")
        }
        throw SwanError.unauthorized("invalid legacy auth body")
    } catch {
        throw SwanError.unauthorized("invalid legacy auth body")
    }
}

/// Maps legacy-auth failures to the spec §3.3 status codes: 401
/// authentication_required, 403 request_not_allowed, 422 field-safe codes,
/// 429 rate limit, 503 service_unavailable. There is no fallback to weaker
/// authentication and no error detail that discloses account state.
private func legacyAuthErrorResponse(for error: any Error) -> Response {
    let status: HTTPResponse.Status
    let code: String
    switch error {
    case let error as SwanError:
        switch error {
        case .unauthorized:
            status = .unauthorized
            code = "authentication_required"
        case .conflict:
            status = .conflict
            code = "conflict"
        case .expired:
            status = HTTPResponse.Status(code: 422)
            code = "expired"
        case .invalidIdentifier, .malformed:
            status = HTTPResponse.Status(code: 422)
            code = "invalid_request"
        case .invalidProfile, .unavailable:
            status = .serviceUnavailable
            code = "service_unavailable"
        }
    case is AccountLoginAdmissionError:
        status = .serviceUnavailable
        code = "service_unavailable"
    case is CancellationError:
        status = .serviceUnavailable
        code = "service_unavailable"
    default:
        status = .serviceUnavailable
        code = "service_unavailable"
    }
    return jsonResponseWithStatus(status, body: ["error": code])
}
