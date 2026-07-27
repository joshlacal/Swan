import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import SwanAccounts
import SwanCore
import SwanOAuth
import SwanStorage

/// The bounded, opt-in browser authorization bridge for the profile's
/// localhost development client. It deliberately does not accept a client
/// metadata URL from a browser form: PAR has already validated the virtual
/// client and stored the complete DPoP/PKCE/redirect binding durably.
enum SwanLocalhostOAuthHTTP {
    static let maximumFormBytes = 16 * 1024
    static let maximumQueryBytes = 12 * 1024
    static let cookieName = "__Host-swan-oauth"
    static let sessionLifetime: TimeInterval = 10 * 60
}

private enum LocalhostOAuthRequestError: Error {
    case malformed
    case payloadTooLarge
}

private struct LocalhostAuthorizeQuery {
    let clientID: URL
    let requestURI: String
}

private struct LocalhostLoginForm {
    let csrf: String
    let handle: String
    let password: String
}

private enum LocalhostConsentDecision: String {
    case approve
    case deny
}

private struct LocalhostConsentForm {
    let csrf: String
    let decision: LocalhostConsentDecision
}

private enum LocalhostTokenGrant: String {
    case authorizationCode = "authorization_code"
    case refreshToken = "refresh_token"
}

private struct LocalhostTokenForm {
    let grant: LocalhostTokenGrant
    let clientID: URL
    let redirectURI: URL?
    let code: String?
    let verifier: String?
    let refreshToken: String?
}

private struct LocalhostRevocationForm {
    let token: String
    let clientID: URL
    let requestedKind: OAuthOpaqueTokenKind?
}

private struct LocalhostTokenSuccess: Encodable {
    let accessToken: String
    let refreshToken: String
    let tokenType = "DPoP"
    let expiresIn: Int
    let scope = "atproto"
    let subject: String

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case scope
        case subject = "sub"
    }
}

private struct LocalhostOAuthError: Encodable {
    let error: String
}

private struct UntrustedLocalDPoPNonce: Decodable {
    let nonce: String
}

/// Register all local browser routes before `Application` construction. The
/// PAR endpoint is registered separately by `SwanHTTPServer` because its
/// strict DPoP form adapter is also useful in PAR-only mode.
func registerLocalhostOAuthEndpoints(
    on router: Router<BasicRequestContext>,
    configuration: SwanLocalhostOAuthConfiguration,
    runtime: SwanOAuthRuntime
) {
    router.get("/oauth/authorize") { request, _ async -> Response in
        await beginLocalhostAuthorization(
            request: request,
            configuration: configuration,
            runtime: runtime
        )
    }
    router.post("/oauth/authorize") { request, _ async -> Response in
        await loginLocalhostAuthorization(
            request: request,
            configuration: configuration,
            runtime: runtime
        )
    }
    router.post("/oauth/authorize/consent") { request, _ async -> Response in
        await consentLocalhostAuthorization(
            request: request,
            configuration: configuration,
            runtime: runtime
        )
    }
    router.post("/oauth/token") { request, _ async -> Response in
        await exchangeLocalhostToken(
            request: request,
            configuration: configuration,
            runtime: runtime
        )
    }
    router.post("/oauth/revoke") { request, _ async -> Response in
        await revokeLocalhostToken(
            request: request,
            configuration: configuration,
            runtime: runtime
        )
    }
}

private func beginLocalhostAuthorization(
    request: Request,
    configuration: SwanLocalhostOAuthConfiguration,
    runtime: SwanOAuthRuntime
) async -> Response {
    let query: LocalhostAuthorizeQuery
    do {
        query = try parseAuthorizeQuery(request)
        let metadata = try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: query.clientID)
        guard metadata.isLocalhostDevelopmentClient,
              let pushed = try await runtime.tokenService.activePushedAuthorizationRequest(query.requestURI),
              pushed.binding.issuer == configuration.issuer.absoluteString,
              pushed.binding.clientID == query.clientID.absoluteString else {
            return localhostAuthorizationError(.badRequest)
        }
        let issued = try runtime.browserSessionService.issue(
            requestURI: query.requestURI,
            lifetime: SwanLocalhostOAuthHTTP.sessionLifetime
        )
        return localhostHTML(
            .ok,
            loginPage(csrf: issued.session.csrfToken),
            setCookie: browserCookie(issued.value)
        )
    } catch {
        // Whether a high-entropy request URI was unknown, consumed, expired,
        // malformed, or database-backed state was unavailable is not a
        // browser-visible oracle.
        return localhostAuthorizationError(.badRequest)
    }
}

private func loginLocalhostAuthorization(
    request: Request,
    configuration: SwanLocalhostOAuthConfiguration,
    runtime: SwanOAuthRuntime
) async -> Response {
    do {
        let form = try await parseLoginForm(request)
        let session = try browserSession(from: request, runtime: runtime)
        guard session.subject == nil,
              form.csrf == session.csrfToken,
              let pushed = try await runtime.tokenService.activePushedAuthorizationRequest(session.requestURI),
              pushed.binding.issuer == configuration.issuer.absoluteString else {
            return localhostAuthorizationError(.badRequest)
        }
        guard let authenticated = await configuration.accounts.authenticate(
            handle: form.handle,
            password: form.password
        ) else {
            return localhostAuthorizationError(.unauthorized)
        }
        let issued = try runtime.browserSessionService.issue(
            requestURI: session.requestURI,
            subject: authenticated.account.did,
            lifetime: session.expiresAt.timeIntervalSinceNow
        )
        return localhostHTML(
            .ok,
            consentPage(csrf: issued.session.csrfToken, subject: authenticated.account.did),
            setCookie: browserCookie(issued.value)
        )
    } catch {
        return localhostAuthorizationError(.badRequest)
    }
}

private func consentLocalhostAuthorization(
    request: Request,
    configuration: SwanLocalhostOAuthConfiguration,
    runtime: SwanOAuthRuntime
) async -> Response {
    let fallback: Response = localhostAuthorizationError(.badRequest, clearCookie: true)
    do {
        let form = try await parseConsentForm(request)
        let session = try browserSession(from: request, runtime: runtime)
        guard let subject = session.subject,
              form.csrf == session.csrfToken,
              let account = try await configuration.accounts.account(did: subject),
              account.status.authorizesAccount,
              let pushed = try await runtime.tokenService.activePushedAuthorizationRequest(session.requestURI),
              pushed.binding.issuer == configuration.issuer.absoluteString else {
            return fallback
        }

        // Consume immediately before emitting a redirect. A transient failure
        // before this point does not consume the PAR; a response race after it
        // cannot mint a second code because the store compares this exact
        // durable binding atomically.
        let consumed = try await runtime.tokenService.consumePushedAuthorizationRequest(
            session.requestURI,
            binding: pushed.binding
        )
        let destination: URL
        switch form.decision {
        case .approve:
            let code = try await runtime.tokenService.issueAuthorizationCode(
                subject: account.did,
                binding: consumed.binding,
                codeChallengeS256: consumed.codeChallengeS256
            )
            destination = try authorizationRedirect(
                base: consumed.binding.redirectURI,
                parameters: [
                    ("code", code), ("state", consumed.state),
                    ("iss", configuration.issuer.absoluteString),
                ]
            )
        case .deny:
            destination = try authorizationRedirect(
                base: consumed.binding.redirectURI,
                parameters: [
                    ("error", "access_denied"), ("state", consumed.state),
                    ("iss", configuration.issuer.absoluteString),
                ]
            )
        }
        return localhostRedirect(destination, clearCookie: true)
    } catch {
        return fallback
    }
}

private func exchangeLocalhostToken(
    request: Request,
    configuration: SwanLocalhostOAuthConfiguration,
    runtime: SwanOAuthRuntime
) async -> Response {
    let form: LocalhostTokenForm
    do {
        form = try await parseTokenForm(request)
    } catch let error as LocalhostOAuthRequestError {
        return switch error {
        case .payloadTooLarge: localhostTokenError(.contentTooLarge)
        case .malformed: localhostTokenError(.badRequest)
        }
    } catch {
        return localhostTokenError(.badRequest)
    }

    guard let proof = localDPoPProof(from: request.headers),
          let nonce = localUntrustedDPoPNonce(from: proof) else {
        return localhostTokenNonceChallenge(runtime: runtime)
    }
    let dpopProof: OAuthValidatedDPoPProof
    do {
        let validator = try OAuthDPoPProofValidator(runtime: runtime)
        dpopProof = try await validator.validate(
            proof,
            request: OAuthDPoPRequest(
                method: "POST",
                target: configuration.issuer.appending(path: "oauth/token"),
                serverNonce: nonce
            )
        )
    } catch let error as SwanError {
        if case .unavailable = error {
            return localhostTokenError(.serviceUnavailable, error: "temporarily_unavailable")
        }
        return localhostTokenNonceChallenge(runtime: runtime)
    } catch {
        return localhostTokenNonceChallenge(runtime: runtime)
    }

    do {
        let pair: OAuthTokenPair
        switch form.grant {
        case .authorizationCode:
            guard let code = form.code, let verifier = form.verifier, let redirectURI = form.redirectURI else {
                return localhostTokenError(.badRequest)
            }
            let metadata = try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: form.clientID)
            let session = try OAuthValidatedSession(
                issuer: configuration.issuer.absoluteString,
                client: OAuthResolvedClientMetadata(metadata: metadata, keySet: nil),
                redirectURI: redirectURI,
                scopes: ["atproto"],
                dpopProof: dpopProof
            )
            pair = try await runtime.tokenService.redeemAuthorizationCode(
                code,
                verifier: verifier,
                session: session,
                requireActiveSubject: true
            )
        case .refreshToken:
            guard let refreshToken = form.refreshToken else { return localhostTokenError(.badRequest) }
            pair = try await runtime.tokenService.redeemLocalhostPublicRefresh(
                refreshToken,
                clientID: form.clientID,
                dpopProof: dpopProof
            )
        }
        let grant = try await runtime.tokenService.validateAccess(
            pair.accessToken,
            proof: dpopProof
        )
        let expiresIn = max(0, Int(pair.accessExpiresAt.timeIntervalSinceNow.rounded(.down)))
        return localhostTokenJSON(
            .ok,
            LocalhostTokenSuccess(
                accessToken: pair.accessToken,
                refreshToken: pair.refreshToken,
                expiresIn: expiresIn,
                subject: grant.subject
            )
        )
    } catch let error as SwanError {
        if case .unavailable = error {
            return localhostTokenError(.serviceUnavailable, error: "temporarily_unavailable")
        }
        // Code/PAR/family existence, PKCE, DPoP JKT, client binding, expiry,
        // and refresh reuse share this response. In particular a reused
        // refresh may revoke its family durably without advertising that fact.
        return localhostTokenError(.badRequest, error: "invalid_grant")
    } catch {
        return localhostTokenError(.serviceUnavailable, error: "temporarily_unavailable")
    }
}

private func revokeLocalhostToken(
    request: Request,
    configuration: SwanLocalhostOAuthConfiguration,
    runtime: SwanOAuthRuntime
) async -> Response {
    let form: LocalhostRevocationForm
    do {
        form = try await parseRevocationForm(request)
    } catch let error as LocalhostOAuthRequestError {
        return switch error {
        case .payloadTooLarge: localhostTokenError(.contentTooLarge)
        case .malformed: localhostTokenError(.badRequest)
        }
    } catch {
        return localhostTokenError(.badRequest)
    }
    guard let proof = localDPoPProof(from: request.headers),
          let nonce = localUntrustedDPoPNonce(from: proof) else {
        return localhostTokenNonceChallenge(runtime: runtime)
    }
    let dpopProof: OAuthValidatedDPoPProof
    do {
        let validator = try OAuthDPoPProofValidator(runtime: runtime)
        dpopProof = try await validator.validate(
            proof,
            request: OAuthDPoPRequest(
                method: "POST",
                target: configuration.issuer.appending(path: "oauth/revoke"),
                serverNonce: nonce
            )
        )
    } catch let error as SwanError {
        if case .unavailable = error {
            return localhostTokenError(.serviceUnavailable, error: "temporarily_unavailable")
        }
        return localhostTokenNonceChallenge(runtime: runtime)
    } catch {
        return localhostTokenNonceChallenge(runtime: runtime)
    }

    do {
        let kinds: [OAuthOpaqueTokenKind]
        if let requestedKind = form.requestedKind {
            kinds = [requestedKind]
        } else {
            // A high-entropy opaque token can only be in one table. Check the
            // refresh table first because a successful match allows whole
            // family revocation without inspecting any access-token value.
            kinds = [.refreshToken, .accessToken]
        }
        for kind in kinds {
            if try await runtime.tokenService.revokeLocalhostPublicToken(
                form.token,
                kind: kind,
                clientID: form.clientID,
                dpopProof: dpopProof
            ) {
                break
            }
        }
        // RFC 7009 deliberately returns 200 whether a token existed, was
        // expired, belonged to another client, or was already revoked.
        return Response(status: .ok, headers: [.cacheControl: "no-store"])
    } catch let error as SwanError {
        if case .unavailable = error {
            return localhostTokenError(.serviceUnavailable, error: "temporarily_unavailable")
        }
        return Response(status: .ok, headers: [.cacheControl: "no-store"])
    } catch {
        return localhostTokenError(.serviceUnavailable, error: "temporarily_unavailable")
    }
}

private func parseAuthorizeQuery(_ request: Request) throws -> LocalhostAuthorizeQuery {
    guard let query = request.uri.query,
          !query.isEmpty, query.utf8.count <= SwanLocalhostOAuthHTTP.maximumQueryBytes else {
        throw LocalhostOAuthRequestError.malformed
    }
    let fields = try strictURLEncodedFields(
        Array(query.utf8),
        maximumBytes: SwanLocalhostOAuthHTTP.maximumQueryBytes
    )
    guard Set(fields.keys) == ["client_id", "request_uri"],
          let clientIDText = fields["client_id"],
          let requestURI = fields["request_uri"],
          clientIDText.utf8.count <= 4_096,
          requestURI.utf8.count <= 256,
          let clientID = URL(string: clientIDText),
          clientID.absoluteString == clientIDText else {
        throw LocalhostOAuthRequestError.malformed
    }
    return LocalhostAuthorizeQuery(clientID: clientID, requestURI: requestURI)
}

private func parseLoginForm(_ request: Request) async throws -> LocalhostLoginForm {
    let fields = try await strictForm(request)
    guard Set(fields.keys) == ["csrf", "handle", "password"],
          let csrf = fields["csrf"], let handle = fields["handle"], let password = fields["password"],
          validBrowserOpaqueValue(csrf),
          !handle.isEmpty, handle.utf8.count <= 253,
          !password.isEmpty, password.utf8.count <= 1_024,
          !password.utf8.contains(0) else {
        throw LocalhostOAuthRequestError.malformed
    }
    return LocalhostLoginForm(csrf: csrf, handle: handle, password: password)
}

private func parseConsentForm(_ request: Request) async throws -> LocalhostConsentForm {
    let fields = try await strictForm(request)
    guard Set(fields.keys) == ["csrf", "decision"],
          let csrf = fields["csrf"], let decisionText = fields["decision"],
          validBrowserOpaqueValue(csrf), let decision = LocalhostConsentDecision(rawValue: decisionText) else {
        throw LocalhostOAuthRequestError.malformed
    }
    return LocalhostConsentForm(csrf: csrf, decision: decision)
}

private func parseTokenForm(_ request: Request) async throws -> LocalhostTokenForm {
    let fields = try await strictForm(request)
    guard let grant = fields["grant_type"].flatMap(LocalhostTokenGrant.init(rawValue:)),
          let clientIDText = fields["client_id"],
          clientIDText.utf8.count <= 4_096,
          let clientID = URL(string: clientIDText), clientID.absoluteString == clientIDText else {
        throw LocalhostOAuthRequestError.malformed
    }
    _ = try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: clientID)
    switch grant {
    case .authorizationCode:
        guard Set(fields.keys) == ["grant_type", "client_id", "redirect_uri", "code", "code_verifier"],
              let redirectText = fields["redirect_uri"], let code = fields["code"], let verifier = fields["code_verifier"],
              let redirectURI = URL(string: redirectText), redirectURI.absoluteString == redirectText,
              validOpaqueToken(code), validPKCEVerifier(verifier) else {
            throw LocalhostOAuthRequestError.malformed
        }
        let metadata = try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: clientID)
        guard metadata.matchesRedirectURI(redirectURI) else { throw LocalhostOAuthRequestError.malformed }
        return LocalhostTokenForm(
            grant: grant, clientID: clientID, redirectURI: redirectURI,
            code: code, verifier: verifier, refreshToken: nil
        )
    case .refreshToken:
        guard Set(fields.keys) == ["grant_type", "client_id", "refresh_token"],
              let refreshToken = fields["refresh_token"], validOpaqueToken(refreshToken) else {
            throw LocalhostOAuthRequestError.malformed
        }
        return LocalhostTokenForm(
            grant: grant, clientID: clientID, redirectURI: nil,
            code: nil, verifier: nil, refreshToken: refreshToken
        )
    }
}

private func parseRevocationForm(_ request: Request) async throws -> LocalhostRevocationForm {
    let fields = try await strictForm(request)
    guard Set(fields.keys) == ["token", "client_id"] || Set(fields.keys) == ["token", "client_id", "token_type_hint"],
          let token = fields["token"], validOpaqueToken(token),
          let clientIDText = fields["client_id"], clientIDText.utf8.count <= 4_096,
          let clientID = URL(string: clientIDText), clientID.absoluteString == clientIDText else {
        throw LocalhostOAuthRequestError.malformed
    }
    _ = try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: clientID)
    let kind: OAuthOpaqueTokenKind?
    switch fields["token_type_hint"] {
    case nil: kind = nil
    case "access_token": kind = .accessToken
    case "refresh_token": kind = .refreshToken
    default: throw LocalhostOAuthRequestError.malformed
    }
    return LocalhostRevocationForm(token: token, clientID: clientID, requestedKind: kind)
}

private func strictForm(_ request: Request) async throws -> [String: String] {
    guard isFormContentType(request.headers) else { throw LocalhostOAuthRequestError.malformed }
    let lengths = request.headers[values: .contentLength]
    guard lengths.count <= 1 else { throw LocalhostOAuthRequestError.malformed }
    if let value = lengths.first {
        guard let length = Int(value), length >= 0 else { throw LocalhostOAuthRequestError.malformed }
        guard length <= SwanLocalhostOAuthHTTP.maximumFormBytes else {
            throw LocalhostOAuthRequestError.payloadTooLarge
        }
    }
    let body: ByteBuffer
    do {
        body = try await request.body.collect(upTo: SwanLocalhostOAuthHTTP.maximumFormBytes)
    } catch is NIOTooManyBytesError {
        throw LocalhostOAuthRequestError.payloadTooLarge
    } catch {
        throw LocalhostOAuthRequestError.malformed
    }
    guard body.readableBytes > 0,
          let bytes = body.getBytes(at: body.readerIndex, length: body.readableBytes) else {
        throw LocalhostOAuthRequestError.malformed
    }
    return try strictURLEncodedFields(bytes, maximumBytes: SwanLocalhostOAuthHTTP.maximumFormBytes)
}

private func isFormContentType(_ headers: HTTPFields) -> Bool {
    let values = headers[values: .contentType]
    guard values.count == 1 else { return false }
    let pieces = values[0].split(separator: ";", omittingEmptySubsequences: false)
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
    guard pieces.first?.lowercased() == "application/x-www-form-urlencoded" else { return false }
    return pieces.count == 1 || (pieces.count == 2 && pieces[1].lowercased() == "charset=utf-8")
}

private func strictURLEncodedFields(_ bytes: [UInt8], maximumBytes: Int) throws -> [String: String] {
    guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw LocalhostOAuthRequestError.malformed }
    var values: [String: String] = [:]
    var start = 0
    for index in 0 ... bytes.count {
        if index == bytes.count || bytes[index] == UInt8(ascii: "&") {
            guard index > start else { throw LocalhostOAuthRequestError.malformed }
            let component = bytes[start ..< index]
            guard let separator = component.firstIndex(of: UInt8(ascii: "=")), separator != component.startIndex else {
                throw LocalhostOAuthRequestError.malformed
            }
            let key = try strictURLDecode(component[..<separator])
            let value = try strictURLDecode(component[component.index(after: separator)...])
            guard values[key] == nil else { throw LocalhostOAuthRequestError.malformed }
            values[key] = value
            start = index + 1
        }
    }
    return values
}

private func strictURLDecode(_ encoded: some Collection<UInt8>) throws -> String {
    var output: [UInt8] = []
    output.reserveCapacity(encoded.count)
    var iterator = encoded.makeIterator()
    while let byte = iterator.next() {
        switch byte {
        case UInt8(ascii: "+"):
            output.append(UInt8(ascii: " "))
        case UInt8(ascii: "%"):
            guard let high = iterator.next(), let low = iterator.next(),
                  let highNibble = localHexNibble(high), let lowNibble = localHexNibble(low) else {
                throw LocalhostOAuthRequestError.malformed
            }
            output.append(highNibble << 4 | lowNibble)
        case 0 ... 31, 127:
            throw LocalhostOAuthRequestError.malformed
        default:
            output.append(byte)
        }
    }
    guard let string = String(bytes: output, encoding: .utf8), !string.utf8.contains(0) else {
        throw LocalhostOAuthRequestError.malformed
    }
    return string
}

private func localHexNibble(_ byte: UInt8) -> UInt8? {
    switch byte {
    case UInt8(ascii: "0") ... UInt8(ascii: "9"): byte - UInt8(ascii: "0")
    case UInt8(ascii: "A") ... UInt8(ascii: "F"): byte - UInt8(ascii: "A") + 10
    case UInt8(ascii: "a") ... UInt8(ascii: "f"): byte - UInt8(ascii: "a") + 10
    default: nil
    }
}

private func browserSession(from request: Request, runtime: SwanOAuthRuntime) throws -> OAuthBrowserApprovalSession {
    let cookieValues = request.headers[values: .cookie]
    guard cookieValues.count == 1,
          let value = singleCookie(named: SwanLocalhostOAuthHTTP.cookieName, header: cookieValues[0]) else {
        throw LocalhostOAuthRequestError.malformed
    }
    return try runtime.browserSessionService.verify(value)
}

private func singleCookie(named name: String, header: String) -> String? {
    var result: String?
    for piece in header.split(separator: ";", omittingEmptySubsequences: false) {
        let trimmed = piece.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let separator = trimmed.firstIndex(of: "=") else { return nil }
        let key = String(trimmed[..<separator])
        let value = String(trimmed[trimmed.index(after: separator)...])
        guard !key.isEmpty, !value.isEmpty else { return nil }
        if key == name {
            guard result == nil, value.utf8.count <= 8 * 1024 else { return nil }
            result = value
        }
    }
    return result
}

private func authorizationRedirect(base: String, parameters: [(String, String)]) throws -> URL {
    guard var components = URLComponents(string: base),
          components.scheme?.lowercased() == "http",
          let host = components.host?.trimmingCharacters(in: CharacterSet(charactersIn: "[]")),
          ["127.0.0.1", "::1"].contains(host),
          components.user == nil, components.password == nil,
          components.fragment == nil,
          !components.percentEncodedPath.isEmpty else {
        throw LocalhostOAuthRequestError.malformed
    }
    let existing = components.queryItems ?? []
    guard !existing.contains(where: { ["code", "state", "error"].contains($0.name) }) else {
        throw LocalhostOAuthRequestError.malformed
    }
    components.queryItems = existing + parameters.map(URLQueryItem.init)
    guard let url = components.url, url.absoluteString.utf8.count <= 8 * 1024 else {
        throw LocalhostOAuthRequestError.malformed
    }
    return url
}

private func browserCookie(_ value: String) -> String {
    "\(SwanLocalhostOAuthHTTP.cookieName)=\(value); Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600"
}

private func expiredBrowserCookie() -> String {
    "\(SwanLocalhostOAuthHTTP.cookieName)=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
}

private func validBrowserOpaqueValue(_ value: String) -> Bool {
    value.utf8.count == 43 && value.utf8.allSatisfy { byte in
        (65 ... 90).contains(byte) || (97 ... 122).contains(byte) ||
            (48 ... 57).contains(byte) || byte == 45 || byte == 95
    }
}

private func validOpaqueToken(_ value: String) -> Bool {
    validBrowserOpaqueValue(value)
}

private func validPKCEVerifier(_ value: String) -> Bool {
    guard (43 ... 128).contains(value.utf8.count) else { return false }
    return value.utf8.allSatisfy { byte in
        (65 ... 90).contains(byte) || (97 ... 122).contains(byte) ||
            (48 ... 57).contains(byte) || [45, 46, 95, 126].contains(byte)
    }
}

private func localDPoPProof(from headers: HTTPFields) -> String? {
    let values = headers[values: HTTPField.Name("DPoP")!]
    guard values.count == 1, !values[0].isEmpty,
          values[0].utf8.count <= 32_768, !values[0].utf8.contains(0) else {
        return nil
    }
    return values[0]
}

private func localUntrustedDPoPNonce(from proof: String) -> String? {
    let parts = proof.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3,
          let payload = try? OAuthBase64URL.decode(String(parts[1]), maxBytes: 16_384),
          let claims = try? JSONDecoder().decode(UntrustedLocalDPoPNonce.self, from: payload),
          !claims.nonce.isEmpty, claims.nonce.utf8.count <= 4_096,
          !claims.nonce.utf8.contains(0) else {
        return nil
    }
    return claims.nonce
}

private func loginPage(csrf: String) -> String {
    """
    <!doctype html><html><head><meta charset="utf-8"><title>Swan sign in</title></head><body><main><h1>Sign in to Swan</h1><form method="post" action="/oauth/authorize"><input type="hidden" name="csrf" value="\(csrf)"><label>Handle <input name="handle" autocomplete="username" required></label><label>Password <input name="password" type="password" autocomplete="current-password" required></label><button type="submit">Continue</button></form></main></body></html>
    """
}

private func consentPage(csrf: String, subject: String) -> String {
    """
    <!doctype html><html><head><meta charset="utf-8"><title>Authorize Swan client</title></head><body><main><h1>Authorize local development client</h1><p>Signed in as \(htmlEscape(subject)).</p><form method="post" action="/oauth/authorize/consent"><input type="hidden" name="csrf" value="\(csrf)"><button name="decision" value="approve" type="submit">Approve</button><button name="decision" value="deny" type="submit">Deny</button></form></main></body></html>
    """
}

private func htmlEscape(_ value: String) -> String {
    value.replacingOccurrences(of: "&", with: "&amp;")
        .replacingOccurrences(of: "<", with: "&lt;")
        .replacingOccurrences(of: ">", with: "&gt;")
        .replacingOccurrences(of: "\"", with: "&quot;")
        .replacingOccurrences(of: "'", with: "&#39;")
}

private func localhostHTML(_ status: HTTPResponse.Status, _ html: String, setCookie: String? = nil) -> Response {
    var headers: HTTPFields = [.contentType: "text/html; charset=utf-8", .cacheControl: "no-store"]
    if let setCookie { headers[HTTPField.Name("Set-Cookie")!] = setCookie }
    return Response(status: status, headers: headers, body: .init(byteBuffer: ByteBuffer(string: html)))
}

private func localhostRedirect(_ destination: URL, clearCookie: Bool) -> Response {
    var headers: HTTPFields = [.location: destination.absoluteString, .cacheControl: "no-store"]
    if clearCookie { headers[HTTPField.Name("Set-Cookie")!] = expiredBrowserCookie() }
    return Response(status: .found, headers: headers)
}

private func localhostAuthorizationError(_ status: HTTPResponse.Status, clearCookie: Bool = false) -> Response {
    var headers: HTTPFields = [.contentType: "text/plain; charset=utf-8", .cacheControl: "no-store"]
    if clearCookie { headers[HTTPField.Name("Set-Cookie")!] = expiredBrowserCookie() }
    return Response(status: status, headers: headers, body: .init(byteBuffer: ByteBuffer(string: "authorization request rejected")))
}

private func localhostTokenNonceChallenge(runtime: SwanOAuthRuntime) -> Response {
    var headers: HTTPFields = [.contentType: "application/json", .cacheControl: "no-store"]
    headers[HTTPField.Name("DPoP-Nonce")!] = runtime.dpopNonceService.issue()
    headers[.wwwAuthenticate] = "DPoP error=\"use_dpop_nonce\""
    let data = (try? JSONEncoder().encode(LocalhostOAuthError(error: "use_dpop_nonce"))) ?? Data("{}".utf8)
    return Response(status: .badRequest, headers: headers, body: .init(byteBuffer: ByteBuffer(data: data)))
}

private func localhostTokenError(
    _ status: HTTPResponse.Status,
    error: String = "invalid_request"
) -> Response {
    localhostTokenJSON(status, LocalhostOAuthError(error: error))
}

private func localhostTokenJSON(_ status: HTTPResponse.Status, _ body: some Encodable) -> Response {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = (try? encoder.encode(body)) ?? Data("{}".utf8)
    return Response(
        status: status,
        headers: [.contentType: "application/json", .cacheControl: "no-store"],
        body: .init(byteBuffer: ByteBuffer(data: data))
    )
}
