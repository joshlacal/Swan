import Foundation
import HTTPTypes
import Hummingbird
import NIOCore
import SwanAccounts
import SwanCore
import SwanOAuth
import SwanStorage

/// Complete HTTP assembly for Swan's public authorization server.  The
/// configuration is only constructed by `SwanHTTPServer` after it has checked
/// the matching publication metadata, durable account directory, and hardened
/// remote client loader.  This file intentionally does not offer individual
/// route registration entry points: PAR, browser authorization, token, and
/// revocation are one security boundary.
enum SwanOAuthAuthorizationServerHTTP {
  static let maximumFormBytes = 48 * 1024
  static let maximumQueryBytes = 12 * 1024
  static let sessionLifetime: TimeInterval = 10 * 60
  static let cookieName = "__Host-swan-oauth"
}

private enum OAuthServerRequestError: Error {
  case malformed
  case payloadTooLarge
}

private struct OAuthServerPARForm {
  let clientID: URL
  let redirectURI: URL
  let scopes: Set<String>
  let state: String
  let codeChallenge: String
  let clientAssertionType: String?
  let clientAssertion: String?
}

private struct OAuthServerAuthorizeQuery {
  let clientID: URL
  let requestURI: String
}

private struct OAuthServerLoginForm {
  let csrf: String
  let handle: String
  let password: String
}

private enum OAuthServerConsentDecision: String {
  case approve
  case deny
}

private struct OAuthServerConsentForm {
  let csrf: String
  let decision: OAuthServerConsentDecision
}

private enum OAuthServerTokenGrant: String {
  case authorizationCode = "authorization_code"
  case refreshToken = "refresh_token"
}

private struct OAuthServerTokenForm {
  let grant: OAuthServerTokenGrant
  let clientID: URL
  let redirectURI: URL?
  let code: String?
  let verifier: String?
  let refreshToken: String?
  let clientAssertionType: String?
  let clientAssertion: String?
}

private struct OAuthServerRevocationForm {
  let clientID: URL
  let token: String
  let kind: OAuthOpaqueTokenKind?
  let clientAssertionType: String?
  let clientAssertion: String?
}

private struct OAuthServerDPoPNonce: Decodable {
  let nonce: String
}

private struct OAuthServerPARError: Encodable { let error: String }
private struct OAuthServerTokenError: Encodable { let error: String }

private struct OAuthServerPARSuccess: Encodable {
  let requestURI: String
  let expiresIn: Int

  enum CodingKeys: String, CodingKey {
    case requestURI = "request_uri"
    case expiresIn = "expires_in"
  }
}

private struct OAuthServerTokenSuccess: Encodable {
  let accessToken: String
  let refreshToken: String
  let expiresIn: Int
  let scope: String
  let tokenType = "DPoP"

  enum CodingKeys: String, CodingKey {
    case accessToken = "access_token"
    case refreshToken = "refresh_token"
    case expiresIn = "expires_in"
    case scope
    case tokenType = "token_type"
  }
}

func registerOAuthAuthorizationServerEndpoints(
  on router: Router<BasicRequestContext>,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime
) {
  router.get("/oauth/authorize") { request, _ async -> Response in
    await beginOAuthServerAuthorization(
      request: request, configuration: configuration, runtime: runtime)
  }
  router.post("/oauth/authorize") { request, _ async -> Response in
    await loginOAuthServerAuthorization(
      request: request, configuration: configuration, runtime: runtime)
  }
  router.post("/oauth/authorize/consent") { request, _ async -> Response in
    await consentOAuthServerAuthorization(
      request: request, configuration: configuration, runtime: runtime)
  }
  router.post("/oauth/token") { request, _ async -> Response in
    await exchangeOAuthServerToken(request: request, configuration: configuration, runtime: runtime)
  }
  router.post("/oauth/revoke") { request, _ async -> Response in
    await revokeOAuthServerToken(request: request, configuration: configuration, runtime: runtime)
  }
}

func registerOAuthAuthorizationServerPAREndpoint(
  on router: Router<BasicRequestContext>,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime
) {
  router.post("/oauth/par") { request, _ async -> Response in
    await handleOAuthServerPAR(request: request, configuration: configuration, runtime: runtime)
  }
}

private func handleOAuthServerPAR(
  request: Request,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime
) async -> Response {
  let form: OAuthServerPARForm
  do {
    form = try await parseOAuthServerPARForm(request)
  } catch let error as OAuthServerRequestError {
    return error == .payloadTooLarge
      ? oauthServerPARJSON(.contentTooLarge, OAuthServerPARError(error: "invalid_request"))
      : oauthServerPARJSON(.badRequest, OAuthServerPARError(error: "invalid_request"))
  } catch {
    return oauthServerPARJSON(.badRequest, OAuthServerPARError(error: "invalid_request"))
  }
  guard let proof = oauthServerSingleDPoP(from: request.headers),
    let nonce = oauthServerUntrustedNonce(from: proof)
  else {
    return oauthServerNonceChallenge(runtime: runtime)
  }
  let dpop: OAuthValidatedDPoPProof
  do {
    dpop = try await OAuthDPoPProofValidator(runtime: runtime).validate(
      proof,
      request: OAuthDPoPRequest(
        method: "POST",
        target: configuration.issuer.appending(path: "oauth/par"),
        serverNonce: nonce
      )
    )
  } catch let error as SwanError {
    if case .unavailable = error {
      return oauthServerPARJSON(
        .serviceUnavailable, OAuthServerPARError(error: "temporarily_unavailable"))
    }
    return oauthServerNonceChallenge(runtime: runtime)
  } catch {
    return oauthServerNonceChallenge(runtime: runtime)
  }
  do {
    let client = try await configuration.clientMetadataLoader.load(clientID: form.clientID)
    guard client.metadata.matchesRedirectURI(form.redirectURI),
      form.scopes.isSubset(of: client.metadata.scopes)
    else {
      return oauthServerPARJSON(.badRequest, OAuthServerPARError(error: "invalid_request"))
    }
    let assertion = try await validateOAuthServerClientAssertion(
      type: form.clientAssertionType,
      value: form.clientAssertion,
      client: client,
      configuration: configuration,
      runtime: runtime
    )
    let session = try OAuthValidatedSession(
      issuer: configuration.issuer.absoluteString,
      client: client,
      redirectURI: form.redirectURI,
      scopes: form.scopes,
      dpopProof: dpop,
      clientAssertion: assertion
    )
    let requestURI = try await runtime.tokenService.createPushedAuthorizationRequest(
      session: session,
      state: form.state,
      codeChallengeS256: form.codeChallenge,
      lifetime: 90
    )
    return oauthServerPARJSON(
      .created, OAuthServerPARSuccess(requestURI: requestURI, expiresIn: 90))
  } catch let error as SwanError {
    if case .unavailable = error {
      return oauthServerPARJSON(
        .serviceUnavailable, OAuthServerPARError(error: "temporarily_unavailable"))
    }
    return oauthServerPARJSON(.badRequest, OAuthServerPARError(error: "invalid_request"))
  } catch {
    return oauthServerPARJSON(
      .serviceUnavailable, OAuthServerPARError(error: "temporarily_unavailable"))
  }
}

private func beginOAuthServerAuthorization(
  request: Request,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime
) async -> Response {
  do {
    let query = try parseOAuthServerAuthorizeQuery(request)
    guard
      let pushed = try await runtime.tokenService.activePushedAuthorizationRequest(
        query.requestURI),
      pushed.binding.issuer == configuration.issuer.absoluteString,
      pushed.binding.clientID == query.clientID.absoluteString
    else {
      return oauthServerAuthorizationError(.badRequest)
    }
    let issued = try runtime.browserSessionService.issue(
      requestURI: query.requestURI,
      lifetime: SwanOAuthAuthorizationServerHTTP.sessionLifetime
    )
    return oauthServerHTML(
      .ok,
      oauthServerLoginPage(csrf: issued.session.csrfToken),
      setCookie: oauthServerCookie(issued.value)
    )
  } catch {
    // Request URI existence and client metadata readiness are not a
    // browser-visible oracle.  The client obtained the high-entropy URI
    // at PAR, where it already received its protocol error.
    return oauthServerAuthorizationError(.badRequest)
  }
}

private func loginOAuthServerAuthorization(
  request: Request,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime
) async -> Response {
  do {
    let form = try await parseOAuthServerLoginForm(request)
    let session = try oauthServerBrowserSession(request, runtime: runtime)
    guard session.subject == nil,
      form.csrf == session.csrfToken,
      let pushed = try await runtime.tokenService.activePushedAuthorizationRequest(
        session.requestURI),
      pushed.binding.issuer == configuration.issuer.absoluteString
    else {
      return oauthServerAuthorizationError(.badRequest)
    }
    guard
      let authenticated = await configuration.accounts.authenticate(
        handle: form.handle, password: form.password)
    else {
      return oauthServerAuthorizationError(.unauthorized)
    }
    let issued = try runtime.browserSessionService.issue(
      requestURI: session.requestURI,
      subject: authenticated.account.did,
      lifetime: session.expiresAt.timeIntervalSinceNow
    )
    return oauthServerHTML(
      .ok,
      oauthServerConsentPage(csrf: issued.session.csrfToken, subject: authenticated.account.did),
      setCookie: oauthServerCookie(issued.value)
    )
  } catch {
    return oauthServerAuthorizationError(.badRequest)
  }
}

private func consentOAuthServerAuthorization(
  request: Request,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime
) async -> Response {
  let fallback = oauthServerAuthorizationError(.badRequest, clearCookie: true)
  do {
    let form = try await parseOAuthServerConsentForm(request)
    let session = try oauthServerBrowserSession(request, runtime: runtime)
    guard let subject = session.subject,
      form.csrf == session.csrfToken,
      let account = try await configuration.accounts.account(did: subject),
      account.status.authorizesAccount,
      let pushed = try await runtime.tokenService.activePushedAuthorizationRequest(
        session.requestURI),
      pushed.binding.issuer == configuration.issuer.absoluteString
    else {
      return fallback
    }
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
      destination = try oauthServerAuthorizationRedirect(
        base: consumed.binding.redirectURI,
        parameters: [("code", code), ("state", consumed.state)]
      )
    case .deny:
      destination = try oauthServerAuthorizationRedirect(
        base: consumed.binding.redirectURI,
        parameters: [("error", "access_denied"), ("state", consumed.state)]
      )
    }
    return oauthServerRedirect(destination, clearCookie: true)
  } catch {
    return fallback
  }
}

private func exchangeOAuthServerToken(
  request: Request,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime
) async -> Response {
  let form: OAuthServerTokenForm
  do {
    form = try await parseOAuthServerTokenForm(request)
  } catch let error as OAuthServerRequestError {
    return error == .payloadTooLarge
      ? oauthServerTokenJSON(.contentTooLarge, OAuthServerTokenError(error: "invalid_request"))
      : oauthServerTokenJSON(.badRequest, OAuthServerTokenError(error: "invalid_request"))
  } catch {
    return oauthServerTokenJSON(.badRequest, OAuthServerTokenError(error: "invalid_request"))
  }
  guard let proof = oauthServerSingleDPoP(from: request.headers),
    let nonce = oauthServerUntrustedNonce(from: proof)
  else {
    return oauthServerNonceChallenge(runtime: runtime)
  }
  let dpop: OAuthValidatedDPoPProof
  do {
    dpop = try await OAuthDPoPProofValidator(runtime: runtime).validate(
      proof,
      request: OAuthDPoPRequest(
        method: "POST",
        target: configuration.issuer.appending(path: "oauth/token"),
        serverNonce: nonce
      )
    )
  } catch let error as SwanError {
    if case .unavailable = error {
      return oauthServerTokenJSON(
        .serviceUnavailable, OAuthServerTokenError(error: "temporarily_unavailable"))
    }
    return oauthServerNonceChallenge(runtime: runtime)
  } catch {
    return oauthServerNonceChallenge(runtime: runtime)
  }
  do {
    // A token endpoint always obtains a new document rather than trusting
    // the PAR cache.  This makes a JWKS rekey/removal effective before a
    // code can become a token family.
    let client = try await configuration.clientMetadataLoader.revalidate(clientID: form.clientID)
    let assertion = try await validateOAuthServerClientAssertion(
      type: form.clientAssertionType,
      value: form.clientAssertion,
      client: client,
      configuration: configuration,
      runtime: runtime
    )
    let issued: OAuthTokenGrantResult
    switch form.grant {
    case .authorizationCode:
      guard let code = form.code, let verifier = form.verifier, let redirectURI = form.redirectURI
      else {
        return oauthServerTokenJSON(.badRequest, OAuthServerTokenError(error: "invalid_request"))
      }
      issued = try await runtime.tokenService.redeemAuthorizationCodeForClient(
        code,
        verifier: verifier,
        redirectURI: redirectURI,
        authorizationServerIssuer: configuration.issuer.absoluteString,
        client: client,
        dpopProof: dpop,
        clientAssertion: assertion
      )
    case .refreshToken:
      guard let refresh = form.refreshToken else {
        return oauthServerTokenJSON(.badRequest, OAuthServerTokenError(error: "invalid_request"))
      }
      issued = try await runtime.tokenService.redeemRefreshForClient(
        refresh,
        client: client,
        authorizationServerIssuer: configuration.issuer.absoluteString,
        dpopProof: dpop,
        clientAssertion: assertion,
        metadataLoader: configuration.clientMetadataLoader
      )
    }
    let expires = max(0, Int(issued.pair.accessExpiresAt.timeIntervalSinceNow.rounded(.down)))
    return oauthServerTokenJSON(
      .ok,
      OAuthServerTokenSuccess(
        accessToken: issued.pair.accessToken,
        refreshToken: issued.pair.refreshToken,
        expiresIn: expires,
        scope: issued.scopes.sorted().joined(separator: " ")
      )
    )
  } catch let error as SwanError {
    if case .unavailable = error {
      return oauthServerTokenJSON(
        .serviceUnavailable, OAuthServerTokenError(error: "temporarily_unavailable"))
    }
    return oauthServerTokenJSON(.badRequest, OAuthServerTokenError(error: "invalid_grant"))
  } catch {
    return oauthServerTokenJSON(
      .serviceUnavailable, OAuthServerTokenError(error: "temporarily_unavailable"))
  }
}

private func revokeOAuthServerToken(
  request: Request,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime
) async -> Response {
  let form: OAuthServerRevocationForm
  do {
    form = try await parseOAuthServerRevocationForm(request)
  } catch let error as OAuthServerRequestError {
    return error == .payloadTooLarge
      ? oauthServerTokenJSON(.contentTooLarge, OAuthServerTokenError(error: "invalid_request"))
      : oauthServerTokenJSON(.badRequest, OAuthServerTokenError(error: "invalid_request"))
  } catch {
    return oauthServerTokenJSON(.badRequest, OAuthServerTokenError(error: "invalid_request"))
  }
  guard let proof = oauthServerSingleDPoP(from: request.headers),
    let nonce = oauthServerUntrustedNonce(from: proof)
  else {
    return oauthServerNonceChallenge(runtime: runtime)
  }
  let dpop: OAuthValidatedDPoPProof
  do {
    dpop = try await OAuthDPoPProofValidator(runtime: runtime).validate(
      proof,
      request: OAuthDPoPRequest(
        method: "POST",
        target: configuration.issuer.appending(path: "oauth/revoke"),
        serverNonce: nonce
      )
    )
  } catch let error as SwanError {
    if case .unavailable = error {
      return oauthServerTokenJSON(
        .serviceUnavailable, OAuthServerTokenError(error: "temporarily_unavailable"))
    }
    return oauthServerNonceChallenge(runtime: runtime)
  } catch {
    return oauthServerNonceChallenge(runtime: runtime)
  }
  do {
    let client = try await configuration.clientMetadataLoader.revalidate(clientID: form.clientID)
    let assertion = try await validateOAuthServerClientAssertion(
      type: form.clientAssertionType,
      value: form.clientAssertion,
      client: client,
      configuration: configuration,
      runtime: runtime
    )
    let kinds: [OAuthOpaqueTokenKind] = form.kind.map { [$0] } ?? [.refreshToken, .accessToken]
    for kind in kinds {
      if try await runtime.tokenService.revokeTokenForClient(
        form.token,
        kind: kind,
        client: client,
        authorizationServerIssuer: configuration.issuer.absoluteString,
        dpopProof: dpop,
        clientAssertion: assertion,
        metadataLoader: configuration.clientMetadataLoader
      ) {
        break
      }
    }
    return Response(status: .ok, headers: [.cacheControl: "no-store"])
  } catch let error as SwanError {
    if case .unavailable = error {
      return oauthServerTokenJSON(
        .serviceUnavailable, OAuthServerTokenError(error: "temporarily_unavailable"))
    }
    // RFC 7009 intentionally provides no token or family existence oracle.
    return Response(status: .ok, headers: [.cacheControl: "no-store"])
  } catch {
    return oauthServerTokenJSON(
      .serviceUnavailable, OAuthServerTokenError(error: "temporarily_unavailable"))
  }
}

private func validateOAuthServerClientAssertion(
  type: String?,
  value: String?,
  client: OAuthResolvedClientMetadata,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime
) async throws -> OAuthValidatedClientAssertion? {
  switch client.metadata.tokenEndpointAuthMethod {
  case .none:
    guard type == nil, value == nil else {
      throw SwanError.unauthorized("public client assertion rejected")
    }
    return nil
  case .privateKeyJWT:
    guard let type, let value,
      value.utf8.count <= 32 * 1024,
      !value.utf8.contains(0)
    else {
      throw SwanError.unauthorized("client assertion required")
    }
    return try await OAuthClientAssertionValidator(runtime: runtime).validate(
      value,
      assertionType: type,
      client: client,
      // AT Protocol's confidential assertion audience is the token
      // endpoint, not an issuer alias or the PAR endpoint.
      authorizationServerIssuer: configuration.issuer.appending(path: "oauth/token").absoluteString
    )
  }
}

private func parseOAuthServerPARForm(_ request: Request) async throws -> OAuthServerPARForm {
  let fields = try await oauthServerForm(request)
  let required: Set<String> = [
    "client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge",
    "code_challenge_method",
  ]
  let optional: Set<String> = ["client_assertion_type", "client_assertion"]
  guard fields.keys.allSatisfy({ required.contains($0) || optional.contains($0) }),
    required.isSubset(of: Set(fields.keys)),
    (fields["client_assertion_type"] == nil) == (fields["client_assertion"] == nil),
    fields["response_type"] == "code", fields["code_challenge_method"] == "S256",
    let clientText = fields["client_id"], let redirectText = fields["redirect_uri"],
    let state = fields["state"], let challenge = fields["code_challenge"],
    let clientID = oauthServerExactURL(clientText),
    let redirectURI = oauthServerExactURL(redirectText),
    clientText.utf8.count <= 4_096, redirectText.utf8.count <= 4_096,
    state.utf8.count > 0, state.utf8.count <= 4_096, oauthServerS256Challenge(challenge)
  else {
    throw OAuthServerRequestError.malformed
  }
  return .init(
    clientID: clientID,
    redirectURI: redirectURI,
    scopes: try oauthServerScopes(fields["scope"] ?? ""),
    state: state,
    codeChallenge: challenge,
    clientAssertionType: fields["client_assertion_type"],
    clientAssertion: fields["client_assertion"]
  )
}

private func parseOAuthServerAuthorizeQuery(_ request: Request) throws -> OAuthServerAuthorizeQuery
{
  guard let query = request.uri.query, !query.isEmpty,
    query.utf8.count <= SwanOAuthAuthorizationServerHTTP.maximumQueryBytes
  else {
    throw OAuthServerRequestError.malformed
  }
  let fields = try oauthServerFields(
    Array(query.utf8), maximumBytes: SwanOAuthAuthorizationServerHTTP.maximumQueryBytes)
  guard Set(fields.keys) == ["client_id", "request_uri"],
    let clientText = fields["client_id"], let requestURI = fields["request_uri"],
    clientText.utf8.count <= 4_096, requestURI.utf8.count <= 256,
    let clientID = oauthServerExactURL(clientText)
  else {
    throw OAuthServerRequestError.malformed
  }
  return .init(clientID: clientID, requestURI: requestURI)
}

private func parseOAuthServerLoginForm(_ request: Request) async throws -> OAuthServerLoginForm {
  let fields = try await oauthServerForm(request)
  guard Set(fields.keys) == ["csrf", "handle", "password"],
    let csrf = fields["csrf"], let handle = fields["handle"], let password = fields["password"],
    oauthServerBrowserOpaque(csrf), !handle.isEmpty, handle.utf8.count <= 253,
    !password.isEmpty, password.utf8.count <= 1_024, !password.utf8.contains(0)
  else {
    throw OAuthServerRequestError.malformed
  }
  return .init(csrf: csrf, handle: handle, password: password)
}

private func parseOAuthServerConsentForm(_ request: Request) async throws -> OAuthServerConsentForm
{
  let fields = try await oauthServerForm(request)
  guard Set(fields.keys) == ["csrf", "decision"], let csrf = fields["csrf"],
    oauthServerBrowserOpaque(csrf),
    let decision = fields["decision"].flatMap(OAuthServerConsentDecision.init(rawValue:))
  else {
    throw OAuthServerRequestError.malformed
  }
  return .init(csrf: csrf, decision: decision)
}

private func parseOAuthServerTokenForm(_ request: Request) async throws -> OAuthServerTokenForm {
  let fields = try await oauthServerForm(request)
  guard let grant = fields["grant_type"].flatMap(OAuthServerTokenGrant.init(rawValue:)),
    let clientText = fields["client_id"], let clientID = oauthServerExactURL(clientText),
    clientText.utf8.count <= 4_096
  else { throw OAuthServerRequestError.malformed }
  let common: Set<String> = ["grant_type", "client_id"]
  guard (fields["client_assertion_type"] == nil) == (fields["client_assertion"] == nil) else {
    throw OAuthServerRequestError.malformed
  }
  switch grant {
  case .authorizationCode:
    let expected = common.union(["redirect_uri", "code", "code_verifier"])
    let expectedWithAssertion = expected.union(["client_assertion_type", "client_assertion"])
    guard Set(fields.keys) == expected || Set(fields.keys) == expectedWithAssertion,
      let redirectText = fields["redirect_uri"], let redirect = oauthServerExactURL(redirectText),
      let code = fields["code"], let verifier = fields["code_verifier"],
      redirectText.utf8.count <= 4_096, oauthServerOpaqueToken(code),
      oauthServerPKCEVerifier(verifier)
    else {
      throw OAuthServerRequestError.malformed
    }
    return .init(
      grant: grant, clientID: clientID, redirectURI: redirect, code: code, verifier: verifier,
      refreshToken: nil, clientAssertionType: fields["client_assertion_type"],
      clientAssertion: fields["client_assertion"])
  case .refreshToken:
    let expected = common.union(["refresh_token"])
    let expectedWithAssertion = expected.union(["client_assertion_type", "client_assertion"])
    guard Set(fields.keys) == expected || Set(fields.keys) == expectedWithAssertion,
      let refresh = fields["refresh_token"], oauthServerOpaqueToken(refresh)
    else {
      throw OAuthServerRequestError.malformed
    }
    return .init(
      grant: grant, clientID: clientID, redirectURI: nil, code: nil, verifier: nil,
      refreshToken: refresh, clientAssertionType: fields["client_assertion_type"],
      clientAssertion: fields["client_assertion"])
  }
}

private func parseOAuthServerRevocationForm(_ request: Request) async throws
  -> OAuthServerRevocationForm
{
  let fields = try await oauthServerForm(request)
  let allowed: Set<String> = [
    "token", "client_id", "token_type_hint", "client_assertion_type", "client_assertion",
  ]
  guard fields.keys.allSatisfy({ allowed.contains($0) }),
    Set(["token", "client_id"]).isSubset(of: Set(fields.keys)),
    (fields["client_assertion_type"] == nil) == (fields["client_assertion"] == nil),
    let token = fields["token"], oauthServerOpaqueToken(token),
    let clientText = fields["client_id"], let clientID = oauthServerExactURL(clientText),
    clientText.utf8.count <= 4_096
  else {
    throw OAuthServerRequestError.malformed
  }
  let kind: OAuthOpaqueTokenKind?
  switch fields["token_type_hint"] {
  case nil: kind = nil
  case "access_token": kind = .accessToken
  case "refresh_token": kind = .refreshToken
  default: throw OAuthServerRequestError.malformed
  }
  return .init(
    clientID: clientID, token: token, kind: kind,
    clientAssertionType: fields["client_assertion_type"],
    clientAssertion: fields["client_assertion"])
}

private func oauthServerForm(_ request: Request) async throws -> [String: String] {
  guard oauthServerFormContentType(request.headers) else { throw OAuthServerRequestError.malformed }
  let lengths = request.headers[values: .contentLength]
  guard lengths.count <= 1 else { throw OAuthServerRequestError.malformed }
  if let value = lengths.first {
    guard let length = Int(value), length >= 0 else { throw OAuthServerRequestError.malformed }
    guard length <= SwanOAuthAuthorizationServerHTTP.maximumFormBytes else {
      throw OAuthServerRequestError.payloadTooLarge
    }
  }
  let body: ByteBuffer
  do {
    body = try await request.body.collect(upTo: SwanOAuthAuthorizationServerHTTP.maximumFormBytes)
  } catch is NIOTooManyBytesError { throw OAuthServerRequestError.payloadTooLarge } catch {
    throw OAuthServerRequestError.malformed
  }
  guard let bytes = body.getBytes(at: body.readerIndex, length: body.readableBytes), !bytes.isEmpty
  else {
    throw OAuthServerRequestError.malformed
  }
  return try oauthServerFields(
    bytes, maximumBytes: SwanOAuthAuthorizationServerHTTP.maximumFormBytes)
}

private func oauthServerFormContentType(_ headers: HTTPFields) -> Bool {
  let values = headers[values: .contentType]
  guard values.count == 1 else { return false }
  let pieces = values[0].split(separator: ";", omittingEmptySubsequences: false).map {
    $0.trimmingCharacters(in: .whitespacesAndNewlines)
  }
  return pieces.first?.lowercased() == "application/x-www-form-urlencoded"
    && (pieces.count == 1 || pieces.count == 2 && pieces[1].lowercased() == "charset=utf-8")
}

private func oauthServerFields(_ bytes: [UInt8], maximumBytes: Int) throws -> [String: String] {
  guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw OAuthServerRequestError.malformed }
  var fields: [String: String] = [:]
  var start = 0
  for index in 0...bytes.count where index == bytes.count || bytes[index] == UInt8(ascii: "&") {
    guard index > start else { throw OAuthServerRequestError.malformed }
    let component = bytes[start..<index]
    guard let separator = component.firstIndex(of: UInt8(ascii: "=")),
      separator != component.startIndex
    else {
      throw OAuthServerRequestError.malformed
    }
    let key = try oauthServerDecode(component[..<separator])
    let value = try oauthServerDecode(component[component.index(after: separator)...])
    guard fields[key] == nil else { throw OAuthServerRequestError.malformed }
    fields[key] = value
    start = index + 1
  }
  return fields
}

private func oauthServerDecode(_ encoded: some Collection<UInt8>) throws -> String {
  var output: [UInt8] = []
  var iterator = encoded.makeIterator()
  while let byte = iterator.next() {
    switch byte {
    case UInt8(ascii: "+"): output.append(UInt8(ascii: " "))
    case UInt8(ascii: "%"):
      guard let high = iterator.next(), let low = iterator.next(),
        let highNibble = oauthServerHex(high), let lowNibble = oauthServerHex(low)
      else { throw OAuthServerRequestError.malformed }
      output.append(highNibble << 4 | lowNibble)
    case 0...31, 127: throw OAuthServerRequestError.malformed
    default: output.append(byte)
    }
  }
  guard let value = String(bytes: output, encoding: .utf8), !value.utf8.contains(0) else {
    throw OAuthServerRequestError.malformed
  }
  return value
}

private func oauthServerHex(_ byte: UInt8) -> UInt8? {
  switch byte {
  case UInt8(ascii: "0")...UInt8(ascii: "9"): byte - UInt8(ascii: "0")
  case UInt8(ascii: "A")...UInt8(ascii: "F"): byte - UInt8(ascii: "A") + 10
  case UInt8(ascii: "a")...UInt8(ascii: "f"): byte - UInt8(ascii: "a") + 10
  default: nil
  }
}

private func oauthServerExactURL(_ raw: String) -> URL? {
  guard raw.utf8.count <= 4_096, let url = URL(string: raw), url.absoluteString == raw else {
    return nil
  }
  return url
}

private func oauthServerScopes(_ raw: String) throws -> Set<String> {
  let values = raw.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
  guard !values.isEmpty, values.count <= 64, values.count == Set(values).count,
    values.allSatisfy({
      !$0.isEmpty && $0.utf8.count <= 256 && $0.utf8.allSatisfy { $0 > 0x20 && $0 < 0x7F }
    })
  else {
    throw OAuthServerRequestError.malformed
  }
  return Set(values)
}

private func oauthServerS256Challenge(_ value: String) -> Bool {
  value.utf8.count == 43
    && value.utf8.allSatisfy {
      (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45
        || $0 == 95
    }
}

private func oauthServerBrowserOpaque(_ value: String) -> Bool { oauthServerS256Challenge(value) }
private func oauthServerOpaqueToken(_ value: String) -> Bool { oauthServerS256Challenge(value) }
private func oauthServerPKCEVerifier(_ value: String) -> Bool {
  (43...128).contains(value.utf8.count)
    && value.utf8.allSatisfy {
      (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0)
        || [45, 46, 95, 126].contains($0)
    }
}

private func oauthServerSingleDPoP(from headers: HTTPFields) -> String? {
  let values = headers[values: HTTPField.Name("DPoP")!]
  guard values.count == 1, !values[0].isEmpty, values[0].utf8.count <= 32 * 1024,
    !values[0].utf8.contains(0)
  else { return nil }
  return values[0]
}

private func oauthServerUntrustedNonce(from proof: String) -> String? {
  let parts = proof.split(separator: ".", omittingEmptySubsequences: false)
  guard parts.count == 3,
    let data = try? OAuthBase64URL.decode(String(parts[1]), maxBytes: 16 * 1024),
    let claims = try? StrictJSON.decode(OAuthServerDPoPNonce.self, from: data),
    !claims.nonce.isEmpty, claims.nonce.utf8.count <= 4_096, !claims.nonce.utf8.contains(0)
  else { return nil }
  return claims.nonce
}

private func oauthServerBrowserSession(_ request: Request, runtime: SwanOAuthRuntime) throws
  -> OAuthBrowserApprovalSession
{
  let values = request.headers[values: .cookie]
  guard values.count == 1,
    let cookie = oauthServerCookieValue(
      named: SwanOAuthAuthorizationServerHTTP.cookieName, header: values[0])
  else { throw OAuthServerRequestError.malformed }
  return try runtime.browserSessionService.verify(cookie)
}

private func oauthServerCookieValue(named name: String, header: String) -> String? {
  var found: String?
  for raw in header.split(separator: ";", omittingEmptySubsequences: false) {
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let separator = trimmed.firstIndex(of: "=") else { return nil }
    let key = String(trimmed[..<separator])
    let value = String(trimmed[trimmed.index(after: separator)...])
    guard !key.isEmpty, !value.isEmpty else { return nil }
    if key == name {
      guard found == nil, value.utf8.count <= 8 * 1024 else { return nil }
      found = value
    }
  }
  return found
}

private func oauthServerAuthorizationRedirect(base: String, parameters: [(String, String)]) throws
  -> URL
{
  guard var components = URLComponents(string: base),
    components.scheme != nil, components.user == nil, components.password == nil,
    components.fragment == nil,
    !components.percentEncodedPath.isEmpty || components.host != nil
  else { throw OAuthServerRequestError.malformed }
  let existing = components.queryItems ?? []
  guard !existing.contains(where: { ["code", "state", "error"].contains($0.name) }) else {
    throw OAuthServerRequestError.malformed
  }
  components.queryItems = existing + parameters.map(URLQueryItem.init)
  guard let destination = components.url, destination.absoluteString.utf8.count <= 8 * 1024 else {
    throw OAuthServerRequestError.malformed
  }
  return destination
}

private func oauthServerCookie(_ value: String) -> String {
  "\(SwanOAuthAuthorizationServerHTTP.cookieName)=\(value); Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600"
}
private func oauthServerExpiredCookie() -> String {
  "\(SwanOAuthAuthorizationServerHTTP.cookieName)=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
}

private func oauthServerLoginPage(csrf: String) -> String {
  "<!doctype html><html><head><meta charset=\"utf-8\"><title>Swan sign in</title></head><body><main><h1>Sign in to Swan</h1><form method=\"post\" action=\"/oauth/authorize\"><input type=\"hidden\" name=\"csrf\" value=\"\(csrf)\"><label>Handle <input name=\"handle\" autocomplete=\"username\" required></label><label>Password <input name=\"password\" type=\"password\" autocomplete=\"current-password\" required></label><button type=\"submit\">Continue</button></form></main></body></html>"
}

private func oauthServerConsentPage(csrf: String, subject: String) -> String {
  "<!doctype html><html><head><meta charset=\"utf-8\"><title>Authorize Swan client</title></head><body><main><h1>Authorize client</h1><p>Signed in as \(oauthServerEscape(subject)).</p><form method=\"post\" action=\"/oauth/authorize/consent\"><input type=\"hidden\" name=\"csrf\" value=\"\(csrf)\"><button name=\"decision\" value=\"approve\" type=\"submit\">Approve</button><button name=\"decision\" value=\"deny\" type=\"submit\">Deny</button></form></main></body></html>"
}

private func oauthServerEscape(_ value: String) -> String {
  value.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
    .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
    .replacingOccurrences(of: "'", with: "&#39;")
}

private func oauthServerHTML(
  _ status: HTTPResponse.Status, _ body: String, setCookie: String? = nil
) -> Response {
  var headers: HTTPFields = [.contentType: "text/html; charset=utf-8", .cacheControl: "no-store"]
  if let setCookie { headers[HTTPField.Name("Set-Cookie")!] = setCookie }
  return Response(
    status: status, headers: headers, body: .init(byteBuffer: ByteBuffer(string: body)))
}

private func oauthServerRedirect(_ destination: URL, clearCookie: Bool) -> Response {
  var headers: HTTPFields = [.location: destination.absoluteString, .cacheControl: "no-store"]
  if clearCookie { headers[HTTPField.Name("Set-Cookie")!] = oauthServerExpiredCookie() }
  return Response(status: .found, headers: headers)
}

private func oauthServerAuthorizationError(_ status: HTTPResponse.Status, clearCookie: Bool = false)
  -> Response
{
  var headers: HTTPFields = [.contentType: "text/plain; charset=utf-8", .cacheControl: "no-store"]
  if clearCookie { headers[HTTPField.Name("Set-Cookie")!] = oauthServerExpiredCookie() }
  return Response(
    status: status, headers: headers,
    body: .init(byteBuffer: ByteBuffer(string: "authorization request rejected")))
}

private func oauthServerNonceChallenge(runtime: SwanOAuthRuntime) -> Response {
  var headers: HTTPFields = [.contentType: "application/json", .cacheControl: "no-store"]
  headers[HTTPField.Name("DPoP-Nonce")!] = runtime.dpopNonceService.issue()
  headers[.wwwAuthenticate] = "DPoP error=\"use_dpop_nonce\""
  return oauthServerJSON(
    .badRequest, OAuthServerTokenError(error: "use_dpop_nonce"), headers: headers)
}

private func oauthServerPARJSON<Body: Encodable>(_ status: HTTPResponse.Status, _ body: Body)
  -> Response
{ oauthServerJSON(status, body) }
private func oauthServerTokenJSON<Body: Encodable>(_ status: HTTPResponse.Status, _ body: Body)
  -> Response
{ oauthServerJSON(status, body) }

private func oauthServerJSON<Body: Encodable>(
  _ status: HTTPResponse.Status, _ body: Body, headers: HTTPFields? = nil
) -> Response {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  let data = (try? encoder.encode(body)) ?? Data("{}".utf8)
  var responseHeaders = headers ?? [.contentType: "application/json", .cacheControl: "no-store"]
  if responseHeaders[.contentType] == nil { responseHeaders[.contentType] = "application/json" }
  if responseHeaders[.cacheControl] == nil { responseHeaders[.cacheControl] = "no-store" }
  return Response(
    status: status, headers: responseHeaders, body: .init(byteBuffer: ByteBuffer(data: data)))
}
