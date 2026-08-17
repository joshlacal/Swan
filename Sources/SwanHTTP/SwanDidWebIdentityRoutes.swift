import Foundation
import HTTPTypes
import Hummingbird
import NIOCore
import SwanAccounts
import SwanCore

/// Registration for the management-session-authenticated did:web identity
/// surface and the public one-time claim endpoint.
///
/// The integration owner installs this before the unknown-public guards and
/// the `/xrpc/**` proxy fallback. The cookie/CSRF/origin policy mirrors the
/// account portal API exactly (spec §3.2): every mutation requires a JSON
/// content type, an `Origin` equal to the configured public origin,
/// `Sec-Fetch-Site: same-origin|none`, and a constant-time match of the
/// management CSRF cookie/header. Management cookies never authenticate XRPC;
/// these routes are the account API surface, not XRPC.
func registerSwanDidWebIdentityRoutes(
    on router: Router<SwanHTTPRequestContext>,
    didWeb: SwanDidWebIdentityHTTP,
    publicOrigin: URL,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) {
    // Public one-time claim endpoint. The nonce is the final path segment; a
    // consumed, released, or unknown reservation 404s. This is deliberately
    // public: the external domain operator must be able to fetch the claim
    // bytes without any Swan credential.
    router.get("/.well-known/swan/did-web-claim/*") { request, _ async -> Response in
        let nonce = String(request.uri.path.split(separator: "/").last ?? "")
        do {
            let result = try await didWeb.claimEndpoint.response(nonce: nonce)
            return Response(
                status: HTTPResponse.Status(integerLiteral: result.status),
                headers: [
                    .contentType: result.contentType,
                    .cacheControl: "no-store",
                ],
                body: .init(byteBuffer: ByteBuffer(data: result.body))
            )
        } catch {
            return didWebAccountError(.serviceUnavailable)
        }
    }

    // Reserve a did:web signing key and one-time claim nonce.
    router.post("/account/api/identity/reserve") { request, context async -> Response in
        guard let session = await didWebAuthenticatedSession(request, didWeb: didWeb, publicOrigin: publicOrigin) else {
            return didWebAccountError(.forbidden)
        }
        do {
            let payload = try await didWebBody(request, context: context, requestBodyAdmission: requestBodyAdmission)
            let input = try didWebDecode(SwanDidWebReserveRequest.self, from: payload)
            let result = try await didWeb.reserve(input, sessionValue: session)
            return didWebJSON(.ok, result)
        } catch {
            return didWebErrorResponse(for: error)
        }
    }

    // Claim a reserved did:web binding (one-time nonce consumption).
    router.post("/account/api/identity/claim") { request, context async -> Response in
        guard let session = await didWebAuthenticatedSession(request, didWeb: didWeb, publicOrigin: publicOrigin) else {
            return didWebAccountError(.forbidden)
        }
        do {
            let payload = try await didWebBody(request, context: context, requestBodyAdmission: requestBodyAdmission)
            let input = try didWebDecode(SwanDidWebClaimRequest.self, from: payload)
            let result = try await didWeb.claim(input, sessionValue: session)
            return didWebJSON(.ok, result)
        } catch {
            return didWebErrorResponse(for: error)
        }
    }

    // Rotate: a new reservation plus a fresh step-up claim.
    router.post("/account/api/identity/rotate") { request, context async -> Response in
        guard let session = await didWebAuthenticatedSession(request, didWeb: didWeb, publicOrigin: publicOrigin) else {
            return didWebAccountError(.forbidden)
        }
        do {
            let payload = try await didWebBody(request, context: context, requestBodyAdmission: requestBodyAdmission)
            let input = try didWebDecode(SwanDidWebRotateRequest.self, from: payload)
            let result = try await didWeb.rotate(input, sessionValue: session)
            return didWebJSON(.ok, result)
        } catch {
            return didWebErrorResponse(for: error)
        }
    }

    // Remove the did:web binding (fresh step-up required).
    router.post("/account/api/identity/remove") { request, context async -> Response in
        guard let session = await didWebAuthenticatedSession(request, didWeb: didWeb, publicOrigin: publicOrigin) else {
            return didWebAccountError(.forbidden)
        }
        do {
            let payload = try await didWebBody(request, context: context, requestBodyAdmission: requestBodyAdmission)
            let input = try didWebDecode(SwanDidWebRemoveRequest.self, from: payload)
            let result = try await didWeb.remove(input, sessionValue: session)
            return didWebJSON(.ok, result)
        } catch {
            return didWebErrorResponse(for: error)
        }
    }

    // Revalidate the current binding against the published DID document.
    router.post("/account/api/identity/reverify") { request, context async -> Response in
        guard let session = await didWebAuthenticatedSession(request, didWeb: didWeb, publicOrigin: publicOrigin) else {
            return didWebAccountError(.forbidden)
        }
        do {
            _ = try await didWebBody(request, context: context, requestBodyAdmission: requestBodyAdmission)
            let result = try await didWeb.reverify(sessionValue: session)
            return didWebJSON(.ok, result)
        } catch {
            return didWebErrorResponse(for: error)
        }
    }

    // The admission decision the owner applies to writes and token issuance.
    router.post("/account/api/identity/admission") { request, context async -> Response in
        guard let session = await didWebAuthenticatedSession(request, didWeb: didWeb, publicOrigin: publicOrigin) else {
            return didWebAccountError(.forbidden)
        }
        do {
            _ = try await didWebBody(request, context: context, requestBodyAdmission: requestBodyAdmission)
            let result = try await didWeb.admission(sessionValue: session)
            return didWebJSON(.ok, result)
        } catch {
            return didWebErrorResponse(for: error)
        }
    }
}

// MARK: - Shared account-API policy (mirrors the portal adapter, spec §3.2)

/// Authenticates the management cookie and CSRF pair with the same origin,
/// fetch-site, and JSON content-type policy as the account portal API.
/// Returns the authenticated session value, or `nil` when any check fails
/// (the caller answers a generic 403, never distinguishing which check).
private func didWebAuthenticatedSession(
    _ request: Request,
    didWeb: SwanDidWebIdentityHTTP,
    publicOrigin: URL
) async -> String? {
    guard didWebMutationHeadersAllow(request, expectedOrigin: publicOrigin),
          let session = didWebAccountCookie(
              named: SwanManagementSessionRuntime.sessionCookieName,
              request: request
          ),
          let csrf = didWebAccountCookie(
              named: SwanManagementSessionRuntime.csrfCookieName,
              request: request
          ),
          let header = request.headers[HTTPField.Name("X-Swan-CSRF")!],
          didWebConstantTime(csrf, header),
          (try? await didWeb.sessions.acceptsCSRF(
              sessionValue: session,
              csrfValue: csrf
          )) == true else {
        return nil
    }
    return session
}

private func didWebMutationHeadersAllow(_ request: Request, expectedOrigin: URL) -> Bool {
    didWebSameOrigin(request, expected: expectedOrigin)
        && didWebFetchSiteAllows(request, requireHeader: true)
        && didWebExactJSONMediaType(request.headers[.contentType])
}

private func didWebExactJSONMediaType(_ value: String?) -> Bool {
    guard let value else { return false }
    let parts = value.split(separator: ";", omittingEmptySubsequences: false)
    return parts.count == 1
        && parts[0].trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() == "application/json"
}

private func didWebSameOrigin(_ request: Request, expected: URL) -> Bool {
    guard let origin = request.headers[HTTPField.Name("Origin")!],
          let expectedComponents = URLComponents(
              url: expected,
              resolvingAgainstBaseURL: false
          ),
          let actual = URL(string: origin),
          let actualComponents = URLComponents(
              url: actual,
              resolvingAgainstBaseURL: false
          ) else {
        return false
    }
    guard actualComponents.user == nil,
          actualComponents.password == nil,
          actualComponents.path.isEmpty || actualComponents.path == "/",
          actualComponents.query == nil,
          actualComponents.fragment == nil else {
        return false
    }
    return actualComponents.scheme?.lowercased()
        == expectedComponents.scheme?.lowercased()
        && actualComponents.host?.lowercased()
            == expectedComponents.host?.lowercased()
        && (actualComponents.port
            ?? (actualComponents.scheme == "https" ? 443 : 80))
            == (expectedComponents.port
                ?? (expectedComponents.scheme == "https" ? 443 : 80))
}

private func didWebFetchSiteAllows(_ request: Request, requireHeader: Bool = false) -> Bool {
    guard let site = request.headers[HTTPField.Name("Sec-Fetch-Site")!] else {
        return !requireHeader
    }
    return site == "same-origin" || site == "none"
}

private func didWebAccountCookie(named name: String, request: Request) -> String? {
    // Hummingbird may surface a single `Cookie: a=1; b=2` header as multiple
    // values split on `;`, so every value must be searched — reading only the
    // first would silently drop the CSRF cookie on real browser requests.
    for header in request.headers[values: .cookie] {
        for part in header.split(separator: ";").map(String.init) {
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("\(name)=") else { continue }
            return String(trimmed.dropFirst(name.count + 1))
        }
    }
    return nil
}

private func didWebConstantTime(_ lhs: String, _ rhs: String) -> Bool {
    guard lhs.utf8.count == rhs.utf8.count else { return false }
    var result: UInt8 = 0
    for (a, b) in zip(lhs.utf8, rhs.utf8) {
        result |= a ^ b
    }
    return result == 0
}

// MARK: - Body admission and responses

private func didWebBody(
    _ request: Request,
    context: SwanHTTPRequestContext,
    requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws -> Data {
    let buffer: SwanAdmittedRequestBody
    do {
        buffer = try await collectAdmittedRequestBody(
            request,
            mediaType: .json,
            admission: requestBodyAdmission.admission,
            policy: requestBodyAdmission.policy,
            maximumBytes: 16 * 1024,
            termination: context.jsonWriteBodyTermination
        )
    } catch {
        throw SwanDidWebIdentityHTTPError.unprocessable("invalid request body")
    }
    defer { withExtendedLifetime(buffer) {} }
    guard buffer.readableBytes > 0,
          let bytes = buffer.getBytes(
              at: buffer.readerIndex,
              length: buffer.readableBytes
          ) else {
        throw SwanDidWebIdentityHTTPError.unprocessable("invalid request body")
    }
    return Data(bytes)
}

/// Decodes an admitted did:web mutation payload. A malformed, missing, or
/// wrongly typed body is a client validation failure (422), never an
/// infrastructure outage (503): the body was already admitted and bounded, so
/// a decode failure cannot be a storage/resolver/key-store fault.
private func didWebDecode<Value: Decodable>(
    _ type: Value.Type,
    from data: Data
) throws -> Value {
    do {
        return try JSONDecoder().decode(type, from: data)
    } catch {
        throw SwanDidWebIdentityHTTPError.unprocessable("invalid request body")
    }
}

private enum DidWebAccountStatus {
    case forbidden
    case serviceUnavailable
}

private func didWebAccountError(_ status: DidWebAccountStatus) -> Response {
    let code: String
    let http: HTTPResponse.Status
    switch status {
    case .forbidden:
        code = "request_not_allowed"
        http = .forbidden
    case .serviceUnavailable:
        code = "service_unavailable"
        http = .serviceUnavailable
    }
    return didWebJSON(http, ["error": code])
}

private func didWebErrorResponse(for error: any Error) -> Response {
    guard let error = error as? SwanDidWebIdentityHTTPError else {
        return didWebAccountError(.serviceUnavailable)
    }
    return didWebJSON(
        HTTPResponse.Status(integerLiteral: error.statusCode),
        ["error": error.code]
    )
}

private func didWebJSON(
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
