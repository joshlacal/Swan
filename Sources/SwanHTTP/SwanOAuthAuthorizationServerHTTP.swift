import Crypto
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
  let authFactorToken: String?
}

private struct OAuthServerMFAForm {
  let csrf: String
  let handle: String
  let kind: AuthenticationFactorKind
  let factorID: String
  let code: String?
  let challenge: String?
  let clientDataJSON: String?
  let authenticatorData: String?
  let credentialID: String?
  let signature: String?

  func payload() throws -> Data {
    var value: [String: Any] = ["kind": kind.rawValue, "factorID": factorID]
    if let code { value["code"] = code }
    if let challenge { value["challenge"] = challenge }
    if let clientDataJSON { value["clientDataJSON"] = clientDataJSON }
    if let authenticatorData { value["authenticatorData"] = authenticatorData }
    if let credentialID { value["credentialID"] = credentialID }
    if let signature { value["signature"] = signature }
    return try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
  }
}

private enum OAuthServerConsentDecision: String {
  case approve
  case deny
}

private struct OAuthServerConsentForm {
  let csrf: String
  let decision: OAuthServerConsentDecision
}

private func oauthServerAuthorizationContext(
  session: OAuthBrowserApprovalSession,
  binding: OAuthClientBinding
) throws -> AccountAuthorizationContext {
  try AccountAuthorizationContext(
    channel: .oauth,
    sessionID: session.csrfToken,
    csrfDigest: Data(SHA256.hash(data: Data(session.csrfToken.utf8))),
    clientID: binding.clientID,
    requestDigest: Data(SHA256.hash(data: Data(session.requestURI.utf8))),
    purpose: "oauthToken")
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
  let refreshToken: String?
  let expiresIn: Int
  let scope: String
  let subject: String
  let tokenType = "DPoP"

  enum CodingKeys: String, CodingKey {
    case accessToken = "access_token"
    case refreshToken = "refresh_token"
    case expiresIn = "expires_in"
    case scope
    case subject = "sub"
    case tokenType = "token_type"
  }
}

func registerOAuthAuthorizationServerEndpoints(
  on router: Router<BasicRequestContext>,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime,
  loginClientIdentityPolicy: SwanLoginClientIdentityPolicy,
  requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) {
  router.get("/oauth/authorize") { request, _ async -> Response in
    await beginOAuthServerAuthorization(
      request: request, configuration: configuration, runtime: runtime)
  }
  router.post("/oauth/authorize") { request, context async -> Response in
    await loginOAuthServerAuthorization(
      request: request, context: context, configuration: configuration, runtime: runtime,
      loginClientIdentityPolicy: loginClientIdentityPolicy,
      requestBodyAdmission: requestBodyAdmission)
  }
  router.post("/oauth/authorize/mfa") { request, context async -> Response in
    await completeOAuthServerAuthorizationMFA(
      request: request, context: context, configuration: configuration, runtime: runtime,
      requestBodyAdmission: requestBodyAdmission)
  }
  router.post("/oauth/authorize/consent") { request, context async -> Response in
    await consentOAuthServerAuthorization(
      request: request, context: context, configuration: configuration, runtime: runtime,
      requestBodyAdmission: requestBodyAdmission)
  }
  router.post("/oauth/token") { request, context async -> Response in
    await exchangeOAuthServerToken(
      request: request, context: context, configuration: configuration, runtime: runtime,
      loginClientIdentityPolicy: loginClientIdentityPolicy,
      requestBodyAdmission: requestBodyAdmission)
  }
  router.on("/oauth/token", method: .options) { _, _ -> Response in
    oauthAPICORSPreflightResponse()
  }
  router.post("/oauth/revoke") { request, context async -> Response in
    await revokeOAuthServerToken(
      request: request, context: context, configuration: configuration, runtime: runtime,
      loginClientIdentityPolicy: loginClientIdentityPolicy,
      requestBodyAdmission: requestBodyAdmission)
  }
  router.on("/oauth/revoke", method: .options) { _, _ -> Response in
    oauthAPICORSPreflightResponse()
  }
}

/// - Parameter loginClientIdentityPolicy: How PAR resolves the requesting
///   client's address for its admission budget. Deliberately required and
///   deliberately not defaulted to `.direct`: behind a trusted proxy, `.direct`
///   returns the proxy's own socket address for every request, so the budget
///   would silently collapse from per-peer to one global bucket while still
///   compiling and still passing its tests.
func registerOAuthAuthorizationServerPAREndpoint(
  on router: Router<BasicRequestContext>,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime,
  loginClientIdentityPolicy: SwanLoginClientIdentityPolicy,
  requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) {
  router.post("/oauth/par") { request, context async -> Response in
    await handleOAuthServerPAR(
      request: request, context: context, configuration: configuration, runtime: runtime,
      loginClientIdentityPolicy: loginClientIdentityPolicy,
      requestBodyAdmission: requestBodyAdmission)
  }
  router.on("/oauth/par", method: .options) { _, _ -> Response in
    oauthAPICORSPreflightResponse()
  }
}

private func handleOAuthServerPAR(
  request: Request,
  context: SwanHTTPRequestContext,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime,
  loginClientIdentityPolicy: SwanLoginClientIdentityPolicy,
  requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async -> Response {
  let form: OAuthServerPARForm
  do {
    form = try await parseOAuthServerPARForm(
      request, context: context, requestBodyAdmission: requestBodyAdmission)
  } catch let failure as SwanRequestBodyCollectionFailure {
    context.logger.info(
      "oauth par rejected",
      metadata: [
        "stage": .string("body_collection"),
        "failure": .string(String(describing: failure)),
      ])
    return oauthServerBodyFailurePAR(failure)
  } catch let error as OAuthScopeAdmissionError {
    // `invalid_scope` is new to Swan and describes the request's own text, so
    // it discloses nothing server-side (§4.8). The subset failure keeps
    // `invalid_request` — that one WOULD leak the client's registration — and
    // the mapping lives on the error, not here, so the two cannot drift.
    context.logger.info(
      "oauth par rejected",
      metadata: [
        "stage": .string("scope_admission"),
        "reason": .string(error.description),
      ])
    return oauthServerPARJSON(
      .badRequest, OAuthServerPARError(error: error.oauthErrorCode))
  } catch let error as OAuthServerRequestError {
    context.logger.info(
      "oauth par rejected",
      metadata: [
        "stage": .string("form_parse"),
        "reason": .string(String(describing: error)),
      ])
    return error == .payloadTooLarge
      ? oauthServerPARJSON(.contentTooLarge, OAuthServerPARError(error: "invalid_request"))
      : oauthServerPARJSON(.badRequest, OAuthServerPARError(error: "invalid_request"))
  } catch {
    context.logger.info(
      "oauth par rejected", metadata: ["stage": .string("form_parse_unexpected")])
    return oauthServerPARJSON(.badRequest, OAuthServerPARError(error: "invalid_request"))
  }
  if await oauthServerPeerAdmission(
    request: request, context: context, policy: loginClientIdentityPolicy) == .rateLimited
  {
    context.logger.info(
      "oauth par rejected", metadata: ["stage": .string("peer_admission")])
    return oauthServerJSON(
      .tooManyRequests, OAuthServerPARError(error: "temporarily_unavailable"),
      headers: oauthServerRetryAfterHeaders())
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
    // The raw `form.scopes.isSubset(of: client.metadata.scopes)` that stood here
    // is now stage C inside `OAuthScopeAdmissionPolicy`, reached through
    // `OAuthValidatedSession` below, because the subset check must canonicalise
    // both sides (§9-D7). Leaving the raw comparison in front of it would reject
    // a client that spelled the same grant differently in its metadata and its
    // request before the canonical form ever ran — the exact false negative the
    // canonicalisation exists to remove.
    guard client.metadata.matchesRedirectURI(form.redirectURI) else {
      // `invalid_request` is deliberately opaque on the wire; record the
      // distinguishing detail server-side so an operator can tell a redirect
      // mismatch from a scope mismatch without instrumenting the client.
      context.logger.info(
        "oauth par rejected",
        metadata: [
          "stage": .string("client_binding"),
          "client_id": .string(form.clientID.absoluteString),
          "redirect_matches": .string("false"),
        ]
      )
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
    // §5.7.5 call site 1. Alongside `OAuthValidatedSession.init` — after stages
    // B/C/E have run over the raw set, because stage C compares *raw requested*
    // against *registered* and both sides must still be in `include:` form.
    //
    // Two jobs, and this is the first: every `include:` must resolve, or the
    // request is refused with `invalid_scope`. It fails HERE rather than at mint
    // so a client learns its permission set is unresolvable while it can still
    // do something about it, instead of after a user has authorized.
    //
    // The second job — building the consent payload — is finished at the consent
    // render below (`loginOAuthServerAuthorization`), which is a different HTTP
    // request in Swan than it is upstream. The expansion is not persisted into
    // the PAR row: the binding must keep the client's own `include:` bytes for
    // §6.7 / §9-D20, and the resolver's document cache serves the render for
    // free inside the 90-second PAR lifetime.
    let expansion = try await OAuthLexiconScopeResolution.expandIncludes(
      form.scopes,
      resolver: runtime.lexiconResolver,
      stage: .pushedAuthorizationRequest
    )
    oauthServerLogEmptyExpansions(expansion.emptyExpansions, context: context, stage: "par")
    let requestURI = try await runtime.tokenService.createPushedAuthorizationRequest(
      session: session,
      state: form.state,
      codeChallengeS256: form.codeChallenge,
      lifetime: 90
    )
    return oauthServerPARJSON(
      .created, OAuthServerPARSuccess(requestURI: requestURI, expiresIn: 90))
  } catch let error as OAuthScopeAdmissionError {
    // Stages B, C and E reach the wire here. `invalid_scope` names a fault in
    // the request's own text; `invalid_request` is retained for the subset
    // failure so the client's registration stays undisclosed (§4.8).
    context.logger.info(
      "oauth par rejected",
      metadata: [
        "stage": .string("scope_admission"),
        "client_id": .string(form.clientID.absoluteString),
        "reason": .string(error.description),
      ]
    )
    return oauthServerPARJSON(
      .badRequest, OAuthServerPARError(error: error.oauthErrorCode))
  } catch let error as OAuthScopeResolutionError {
    // §5.7.5: `invalid_scope` here, `invalid_request` at token mint, for the
    // SAME root cause. The asymmetry is upstream's
    // (`request-manager.ts:293-312` vs `token-manager.ts:135-138`) and is kept
    // for interop rather than silently unified; the code comes off the error's
    // stage so the two legs cannot drift.
    context.logger.info(
      "oauth par rejected",
      metadata: [
        "stage": .string("lexicon_resolution"),
        "client_id": .string(form.clientID.absoluteString),
        "reason": .string(error.description),
      ]
    )
    return oauthServerPARJSON(
      .badRequest, OAuthServerPARError(error: error.oauthErrorCode))
  } catch let error as SwanError {
    if case .unavailable = error {
      context.logger.info(
        "oauth par unavailable", metadata: ["reason": .string(error.description)])
      return oauthServerPARJSON(
        .serviceUnavailable, OAuthServerPARError(error: "temporarily_unavailable"))
    }
    // Same rationale as the client-binding guard: the wire error stays
    // opaque, but the operator gets the specific reason. `SwanError`
    // descriptions are fixed diagnostic strings and carry no credential.
    context.logger.info(
      "oauth par rejected",
      metadata: [
        "stage": .string("client_validation"),
        "reason": .string(error.description),
      ]
    )
    return oauthServerPARJSON(.badRequest, OAuthServerPARError(error: "invalid_request"))
  } catch {
    context.logger.info(
      "oauth par failed", metadata: ["stage": .string("unexpected")])
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
      SwanBrowserPages.login(csrf: issued.session.csrfToken),
      setCookie: oauthServerCookie(issued.value),
      formActionSource: oauthServerFormActionSource(pushed.binding.redirectURI)
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
  context: SwanHTTPRequestContext,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime,
  loginClientIdentityPolicy: SwanLoginClientIdentityPolicy,
  requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async -> Response {
  do {
    let form = try await parseOAuthServerLoginForm(
      request, context: context, requestBodyAdmission: requestBodyAdmission)
    let session = try oauthServerBrowserSession(request, runtime: runtime)
    guard session.subject == nil,
      form.csrf == session.csrfToken,
      let pushed = try await runtime.tokenService.activePushedAuthorizationRequest(
        session.requestURI),
      pushed.binding.issuer == configuration.issuer.absoluteString
    else {
      return oauthServerAuthorizationError(.badRequest)
    }
    let clientIPAddress = try loginClientIdentityPolicy.clientIPAddress(
      directPeer: context.remoteAddress?.ipAddress,
      headers: request.headers
    )
    switch try await configuration.accounts.admitLogin(
      handle: form.handle,
      directPeer: clientIPAddress
    ) {
    case .rateLimited:
      return oauthServerAuthorizationError(.tooManyRequests)
    case .allowed:
      break
    }
    let authorizationContext = try oauthServerAuthorizationContext(
      session: session, binding: pushed.binding)
    let authenticated: AccountAuthenticationSuccess
    let outcome: AccountLoginAuthenticationOutcome
    if let grantDirectory = configuration.accounts as? any SwanAccountPortalAuthorizationGrantAccountDirectory {
      outcome = try await grantDirectory.authenticateForLogin(
        handle: form.handle,
        password: form.password,
        authFactorToken: form.authFactorToken,
        authorizationContext: authorizationContext,
        now: Date())
    } else {
      outcome = try await configuration.accounts.authenticateForLogin(
        handle: form.handle,
        password: form.password,
        authFactorToken: form.authFactorToken,
        authFactorSessionID: session.csrfToken)
    }
    switch outcome {
    case let .authenticated(passwordProof) where passwordProof.requiresFactor:
      guard let mfa = configuration.mfaService else {
        return oauthServerAuthorizationError(.unauthorized)
      }
      let challenge = try await mfa.beginOAuthFactor(
        accountDID: passwordProof.account.did,
        sessionID: session.csrfToken,
        context: authorizationContext,
        factorID: nil,
        now: Date())
      let nonce = oauthServerCSPNonce()
      return oauthServerHTML(
        .ok,
        oauthServerMFAChallengePage(
          csrf: session.csrfToken,
          handle: form.handle,
          factor: challenge,
          nonce: nonce),
        formActionSource: oauthServerFormActionSource(pushed.binding.redirectURI),
        cspNonce: nonce)
    case .rejected:
      // A rejected phase-one attempt is terminal. Do not run a second
      // password verification here: doing so would turn a browser form into
      // an unbounded Argon2 oracle and would bypass the single admitted
      // password phase required by the OAuth MFA protocol.
      return oauthServerAuthorizationError(.unauthorized)
    case let .authenticated(success):
      authenticated = success
    }
    let issued = try runtime.browserSessionService.issue(
      requestURI: session.requestURI,
      subject: authenticated.account.did,
      subjectUpdatedAt: authenticated.account.updatedAt,
      authorizationGrantDigest: authenticated.authorizationGrantDigest,
      csrfToken: session.csrfToken,
      lifetime: session.expiresAt.timeIntervalSinceNow
    )
    // §5.7.5 call site 1's second job. `include:` → concrete grants happens
    // BEFORE the renderer extracts space types for display
    // (`lexicon-manager.ts:21-36`), so the person authorizing sees the actual
    // capabilities rather than an opaque permission-set name.
    //
    // Re-resolving here rather than carrying the PAR-time expansion is
    // deliberate: it costs one cache read (the row was proved seconds ago, well
    // inside the 5-minute refresh threshold), and the alternative — persisting a
    // rendered payload into the PAR row — would put a display artifact in the
    // durable binding that §6.7 defines as the client's own requested bytes.
    //
    // A failure here is fatal to the flow rather than a degraded render: a
    // consent page that cannot say what is being granted must not be shown.
    let expansion = try await OAuthLexiconScopeResolution.expandIncludes(
      pushed.binding.scopes,
      resolver: runtime.lexiconResolver,
      stage: .pushedAuthorizationRequest
    )
    oauthServerLogEmptyExpansions(expansion.emptyExpansions, context: context, stage: "consent")
    return oauthServerHTML(
      .ok,
      SwanBrowserPages.consent(
        csrf: issued.session.csrfToken,
        subject: authenticated.account.did,
        clientID: pushed.binding.clientID,
        scopes: expansion.scopes,
        emptyPermissionSets: expansion.emptyExpansions
      ),
      setCookie: oauthServerCookie(issued.value),
      formActionSource: oauthServerFormActionSource(pushed.binding.redirectURI)
    )
  } catch is AccountLoginAdmissionError {
    // All four of these render identically on the wire, deliberately: a
    // distinguishable response would be a credential oracle. Record which one
    // actually fired so an operator is not left guessing between "wrong
    // password", "rate limited" and "proxy peer not trusted".
    context.logger.info(
      "oauth authorize rejected", metadata: ["stage": .string("login_admission")])
    return oauthServerAuthorizationError(.serviceUnavailable)
  } catch is AccountLoginAuthenticationError {
    context.logger.info(
      "oauth authorize rejected", metadata: ["stage": .string("login_authentication")])
    return oauthServerAuthorizationError(.serviceUnavailable)
  } catch is SwanLoginClientIdentityError {
    context.logger.info(
      "oauth authorize rejected", metadata: ["stage": .string("login_client_identity")])
    return oauthServerAuthorizationError(.serviceUnavailable)
  } catch let error as OAuthScopeResolutionError {
    // The browser gets the same opaque page every other authorize failure gets —
    // this is not the leg that reports OAuth error codes to the client, which
    // already had its `invalid_scope` answer at PAR. The operator gets the NSID.
    context.logger.info(
      "oauth authorize rejected",
      metadata: [
        "stage": .string("lexicon_resolution"),
        "reason": .string(error.description),
      ])
    return oauthServerAuthorizationError(.badRequest)
  } catch let failure as SwanRequestBodyCollectionFailure {
    context.logger.info(
      "oauth authorize rejected",
      metadata: [
        "stage": .string("body_collection"),
        "failure": .string(String(describing: failure)),
      ])
    return oauthServerAuthorizationError(
      failure == .unavailable ? .serviceUnavailable : .badRequest)
  } catch {
    context.logger.info(
      "oauth authorize rejected", metadata: ["stage": .string("unexpected")])
    return oauthServerAuthorizationError(.badRequest)
  }
}

private func completeOAuthServerAuthorizationMFA(
  request: Request,
  context: SwanHTTPRequestContext,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime,
  requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async -> Response {
  do {
    guard let mfa = configuration.mfaService else {
      return oauthServerAuthorizationError(.unauthorized)
    }
    let form = try await parseOAuthServerMFAForm(
      request, context: context, requestBodyAdmission: requestBodyAdmission)
    let session = try oauthServerBrowserSession(request, runtime: runtime)
    guard session.subject == nil,
      form.csrf == session.csrfToken,
      let pushed = try await runtime.tokenService.activePushedAuthorizationRequest(session.requestURI),
      pushed.binding.issuer == configuration.issuer.absoluteString,
      let account = try await configuration.accounts.resolve(handle: form.handle),
      account.status.authorizesAccount
    else {
      return oauthServerAuthorizationError(.badRequest)
    }
    let authorizationContext = try oauthServerAuthorizationContext(
      session: session, binding: pushed.binding)
    let proof = try await mfa.verifyOAuthFactor(
      accountDID: account.did,
      sessionID: session.csrfToken,
      context: authorizationContext,
      payload: try form.payload(),
      now: Date())
    guard let token = proof.factorToken else {
      return oauthServerAuthorizationError(.unauthorized)
    }
    guard let grantDirectory = configuration.accounts as? any SwanAccountPortalAuthorizationGrantAccountDirectory else {
      return oauthServerAuthorizationError(.serviceUnavailable)
    }
    let authenticated: AccountAuthenticationSuccess
    switch try await grantDirectory.authenticateFactorForLogin(
      accountDID: account.did,
      authFactorToken: token,
      authorizationContext: authorizationContext,
      now: Date()) {
    case .rejected:
      return oauthServerAuthorizationError(.unauthorized)
    case let .authenticated(value):
      authenticated = value
    }
    guard authenticated.account.did == account.did else {
      return oauthServerAuthorizationError(.unauthorized)
    }
    let issued = try runtime.browserSessionService.issue(
      requestURI: session.requestURI,
      subject: authenticated.account.did,
      subjectUpdatedAt: authenticated.account.updatedAt,
      authorizationGrantDigest: authenticated.authorizationGrantDigest,
      csrfToken: session.csrfToken,
      lifetime: session.expiresAt.timeIntervalSinceNow)
    let expansion = try await OAuthLexiconScopeResolution.expandIncludes(
      pushed.binding.scopes, resolver: runtime.lexiconResolver, stage: .pushedAuthorizationRequest)
    oauthServerLogEmptyExpansions(expansion.emptyExpansions, context: context, stage: "consent")
    return oauthServerHTML(
      .ok,
      oauthServerConsentPage(
        csrf: issued.session.csrfToken,
        subject: authenticated.account.did,
        clientID: pushed.binding.clientID,
        scopes: expansion.scopes,
        emptyPermissionSets: expansion.emptyExpansions),
      setCookie: oauthServerCookie(issued.value),
      formActionSource: oauthServerFormActionSource(pushed.binding.redirectURI))
  } catch is SwanRequestBodyCollectionFailure {
    return oauthServerAuthorizationError(.badRequest)
  } catch is AccountLoginAuthenticationError {
    return oauthServerAuthorizationError(.serviceUnavailable)
  } catch {
    return oauthServerAuthorizationError(.unauthorized)
  }
}

private func consentOAuthServerAuthorization(
  request: Request,
  context: SwanHTTPRequestContext,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime,
  requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async -> Response {
  let fallback = oauthServerAuthorizationError(.badRequest, clearCookie: true)
  do {
    let form = try await parseOAuthServerConsentForm(
      request, context: context, requestBodyAdmission: requestBodyAdmission)
    let session = try oauthServerBrowserSession(request, runtime: runtime)
    guard let subject = session.subject,
      let subjectRevision = session.subjectRevisionMicroseconds,
      form.csrf == session.csrfToken,
      let account = try await configuration.accounts.account(did: subject),
      account.status.authorizesAccount,
      OAuthBrowserSessionService.subjectRevisionMicroseconds(
        for: account.updatedAt
      ) == subjectRevision,
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
    let authorizationContext = try oauthServerAuthorizationContext(
      session: session, binding: consumed.binding)
    let destination: URL
    switch form.decision {
    case .approve:
      guard let authorizationGrantDigest = session.authorizationGrantDigest else {
        return fallback
      }
      let code = try await runtime.tokenService.issueAuthorizationCode(
        subject: account.did,
        binding: consumed.binding,
        codeChallengeS256: consumed.codeChallengeS256,
        activeSubjectRevisionMicroseconds: subjectRevision,
        authorizationGrantDigest: authorizationGrantDigest,
        authorizationContext: authorizationContext
      )
      destination = try oauthServerAuthorizationRedirect(
        base: consumed.binding.redirectURI,
        parameters: [
          ("code", code), ("state", consumed.state),
          ("iss", configuration.issuer.absoluteString),
        ]
      )
    case .deny:
      destination = try oauthServerAuthorizationRedirect(
        base: consumed.binding.redirectURI,
        parameters: [
          ("error", "access_denied"), ("state", consumed.state),
          ("iss", configuration.issuer.absoluteString),
        ]
      )
    }
    return oauthServerRedirect(destination, clearCookie: true)
  } catch let failure as SwanRequestBodyCollectionFailure {
    return failure == .unavailable
      ? oauthServerAuthorizationError(.serviceUnavailable, clearCookie: true)
      : fallback
  } catch {
    return fallback
  }
}

private func exchangeOAuthServerToken(
  request: Request,
  context: SwanHTTPRequestContext,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime,
  loginClientIdentityPolicy: SwanLoginClientIdentityPolicy,
  requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async -> Response {
  let form: OAuthServerTokenForm
  do {
    form = try await parseOAuthServerTokenForm(
      request, context: context, requestBodyAdmission: requestBodyAdmission)
  } catch let failure as SwanRequestBodyCollectionFailure {
    return oauthServerBodyFailureToken(failure)
  } catch let error as OAuthServerRequestError {
    return error == .payloadTooLarge
      ? oauthServerTokenJSON(.contentTooLarge, OAuthServerTokenError(error: "invalid_request"))
      : oauthServerTokenJSON(.badRequest, OAuthServerTokenError(error: "invalid_request"))
  } catch {
    return oauthServerTokenJSON(.badRequest, OAuthServerTokenError(error: "invalid_request"))
  }
  if await oauthServerPeerAdmission(
    request: request, context: context, policy: loginClientIdentityPolicy) == .rateLimited
  {
    context.logger.info(
      "oauth token rejected", metadata: ["stage": .string("peer_admission")])
    return oauthServerJSON(
      .tooManyRequests, OAuthServerTokenError(error: "temporarily_unavailable"),
      headers: oauthServerRetryAfterHeaders())
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
    let expires = max(0, Int(issued.accessExpiresAt.timeIntervalSinceNow.rounded(.down)))
    return oauthServerTokenJSON(
      .ok,
      OAuthServerTokenSuccess(
        accessToken: issued.accessToken,
        refreshToken: issued.refreshToken,
        expiresIn: expires,
        scope: issued.scopes.sorted().joined(separator: " "),
        subject: issued.subject
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
  context: SwanHTTPRequestContext,
  configuration: SwanOAuthAuthorizationServerConfiguration,
  runtime: SwanOAuthRuntime,
  loginClientIdentityPolicy: SwanLoginClientIdentityPolicy,
  requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async -> Response {
  let form: OAuthServerRevocationForm
  do {
    form = try await parseOAuthServerRevocationForm(
      request, context: context, requestBodyAdmission: requestBodyAdmission)
  } catch let failure as SwanRequestBodyCollectionFailure {
    return oauthServerBodyFailureToken(failure)
  } catch let error as OAuthServerRequestError {
    return error == .payloadTooLarge
      ? oauthServerTokenJSON(.contentTooLarge, OAuthServerTokenError(error: "invalid_request"))
      : oauthServerTokenJSON(.badRequest, OAuthServerTokenError(error: "invalid_request"))
  } catch {
    return oauthServerTokenJSON(.badRequest, OAuthServerTokenError(error: "invalid_request"))
  }
  if await oauthServerPeerAdmission(
    request: request, context: context, policy: loginClientIdentityPolicy) == .rateLimited
  {
    context.logger.info(
      "oauth revoke rejected", metadata: ["stage": .string("peer_admission")])
    return oauthServerJSON(
      .tooManyRequests, OAuthServerTokenError(error: "temporarily_unavailable"),
      headers: oauthServerRetryAfterHeaders())
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
    var headers: HTTPFields = [.cacheControl: "no-store"]
    oauthAPICORSHeaders(&headers)
    return Response(status: .ok, headers: headers)
  } catch let error as SwanError {
    if case .unavailable = error {
      return oauthServerTokenJSON(
        .serviceUnavailable, OAuthServerTokenError(error: "temporarily_unavailable"))
    }
    // RFC 7009 intentionally provides no token or family existence oracle.
    var headers: HTTPFields = [.cacheControl: "no-store"]
    oauthAPICORSHeaders(&headers)
    return Response(status: .ok, headers: headers)
  } catch {
    return oauthServerTokenJSON(
      .serviceUnavailable, OAuthServerTokenError(error: "temporarily_unavailable"))
  }
}

/// Charges one request against its peer's budget for the unauthenticated
/// OAuth protocol endpoints, before any DPoP proof is validated.
///
/// `OAuthDPoPProofValidator.validate` durably claims the proof's `jti` in a
/// globally bounded replay table, and on PAR it does so before client
/// metadata has been loaded — so the allocation happens with no client
/// identity established, and exhausting the table denies DPoP validation on
/// every route that uses it. Reordering the claim behind client validation is
/// not available here: on PAR, establishing the client *is* the remote
/// metadata fetch, so that order would put an attacker-selected outbound
/// fetch first. Refusing the request instead leaves the replay namespace
/// global over the `jti`, which is what RFC 9449 requires.
///
/// A peer whose address cannot be resolved is charged to one shared bucket
/// rather than admitted or rejected; see `OAuthPeerAdmissionService`.
///
/// Placement matters and is not arbitrary. This runs *after* the form has been
/// fully collected, so a refusal leaves no half-read body holding a listener
/// connection slot, and needs no drain. Moving it ahead of body collection
/// would require `drainRejectedRequestBody`, which reserves from the very JSON
/// write pool an earlier check would be protecting — an admission control that
/// drains through the resource it guards is not a control. The body's own
/// lease is already released by then: `collectAdmittedRequestBody` hands back a
/// `SwanAdmittedRequestBody` whose `deinit` releases it, and that happens when
/// `oauthServerForm` returns.
private func oauthServerPeerAdmission(
  request: Request,
  context: SwanHTTPRequestContext,
  policy: SwanLoginClientIdentityPolicy
) async -> OAuthPeerAdmissionDecision {
  let peer = try? policy.clientIPAddress(
    directPeer: context.remoteAddress?.ipAddress,
    headers: request.headers
  )
  return await OAuthPeerAdmissionService.shared.admit(peer: peer)
}

private func oauthServerRetryAfterHeaders() -> HTTPFields {
  var headers: HTTPFields = [.contentType: "application/json", .cacheControl: "no-store"]
  headers[HTTPField.Name("Retry-After")!] = String(
    Int(OAuthPeerAdmissionPolicy.defaultWindow.rounded(.up)))
  return headers
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
      // AT Protocol binds confidential client assertions to the stable
      // authorization-server issuer, not a particular endpoint.
      authorizationServerIssuer: configuration.issuer.absoluteString
    )
  }
}

private func parseOAuthServerPARForm(
  _ request: Request,
  context: SwanHTTPRequestContext,
  requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws -> OAuthServerPARForm {
  let fields = try await oauthServerForm(
    request, context: context, requestBodyAdmission: requestBodyAdmission)
  let required: Set<String> = [
    "client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge",
    "code_challenge_method",
  ]
  // `login_hint` and `prompt` are hints ATProto clients send with every
  // sign-in (the atproto-oauth Rust crate includes the typed handle as
  // `login_hint` unconditionally), so refusing them refuses those clients
  // outright. Swan always presents the interactive login form, which is a
  // conforming answer to `login`, `consent`, and `select_account` — but not
  // to `none`, which demands a silent answer this server can never give, so
  // `none` stays refused rather than dishonestly accepted.
  let optional: Set<String> = [
    "client_assertion_type", "client_assertion", "login_hint", "prompt",
  ]
  guard fields.keys.allSatisfy({ required.contains($0) || optional.contains($0) }),
    required.isSubset(of: Set(fields.keys)),
    (fields["client_assertion_type"] == nil) == (fields["client_assertion"] == nil),
    fields["login_hint"].map({ !$0.isEmpty && $0.utf8.count <= 2_048 }) ?? true,
    fields["prompt"].map({ ["login", "consent", "select_account"].contains($0) }) ?? true,
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

private func parseOAuthServerLoginForm(
  _ request: Request,
  context: SwanHTTPRequestContext,
  requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws -> OAuthServerLoginForm {
  let fields = try await oauthServerForm(
    request, context: context, requestBodyAdmission: requestBodyAdmission)
  guard Set(fields.keys) == ["csrf", "handle", "password"]
      || Set(fields.keys) == ["csrf", "handle", "password", "authFactorToken"],
    let csrf = fields["csrf"], let handle = fields["handle"], let password = fields["password"],
    oauthServerBrowserOpaque(csrf), !handle.isEmpty, handle.utf8.count <= 253,
    !password.isEmpty, password.utf8.count <= 1_024, !password.utf8.contains(0)
  else {
    throw OAuthServerRequestError.malformed
  }
  let authFactorToken = fields["authFactorToken"]
  if let authFactorToken, !oauthServerOpaqueToken(authFactorToken) {
    throw OAuthServerRequestError.malformed
  }
  return .init(csrf: csrf, handle: handle, password: password, authFactorToken: authFactorToken)
}

private func parseOAuthServerMFAForm(
  _ request: Request,
  context: SwanHTTPRequestContext,
  requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws -> OAuthServerMFAForm {
  let fields = try await oauthServerForm(
    request, context: context, requestBodyAdmission: requestBodyAdmission)
  // `password` remains an accepted legacy field for clients that cached the
  // old form, but it is never read or verified in phase two.
  let allowed: Set<String> = ["csrf", "handle", "password", "kind", "factorID", "code", "challenge", "clientDataJSON", "authenticatorData", "credentialID", "signature"]
  guard Set(fields.keys).isSubset(of: allowed),
    let csrf = fields["csrf"], oauthServerBrowserOpaque(csrf),
    let handle = fields["handle"], !handle.isEmpty, handle.utf8.count <= 253,
    let kindText = fields["kind"], let kind = AuthenticationFactorKind(rawValue: kindText),
    let factorID = fields["factorID"], !factorID.isEmpty, factorID.utf8.count <= 128,
    fields.values.allSatisfy({ $0.utf8.count <= 16 * 1024 && !$0.utf8.contains(0) })
  else { throw OAuthServerRequestError.malformed }
  return OAuthServerMFAForm(
    csrf: csrf, handle: handle, kind: kind, factorID: factorID,
    code: fields["code"], challenge: fields["challenge"], clientDataJSON: fields["clientDataJSON"],
    authenticatorData: fields["authenticatorData"], credentialID: fields["credentialID"], signature: fields["signature"])
}

private func parseOAuthServerConsentForm(
  _ request: Request,
  context: SwanHTTPRequestContext,
  requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws -> OAuthServerConsentForm
{
  let fields = try await oauthServerForm(
    request, context: context, requestBodyAdmission: requestBodyAdmission)
  guard Set(fields.keys) == ["csrf", "decision"], let csrf = fields["csrf"],
    oauthServerBrowserOpaque(csrf),
    let decision = fields["decision"].flatMap(OAuthServerConsentDecision.init(rawValue:))
  else {
    throw OAuthServerRequestError.malformed
  }
  return .init(csrf: csrf, decision: decision)
}

private func parseOAuthServerTokenForm(
  _ request: Request,
  context: SwanHTTPRequestContext,
  requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws -> OAuthServerTokenForm {
  let fields = try await oauthServerForm(
    request, context: context, requestBodyAdmission: requestBodyAdmission)
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
    // The atproto-oauth Rust crate sends the registered redirect_uri with
    // every refresh. RFC 6749 gives it no role in this grant — the family
    // is already bound to its client — so it is bounds-checked and ignored
    // rather than refused: refusing it broke every Bulleted session at its
    // first refresh while the sign-in that minted the family succeeded.
    var keys = Set(fields.keys)
    if let redirectText = fields["redirect_uri"] {
      guard redirectText.utf8.count <= 4_096, oauthServerExactURL(redirectText) != nil else {
        throw OAuthServerRequestError.malformed
      }
      keys.remove("redirect_uri")
    }
    let expected = common.union(["refresh_token"])
    let expectedWithAssertion = expected.union(["client_assertion_type", "client_assertion"])
    guard keys == expected || keys == expectedWithAssertion,
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

private func parseOAuthServerRevocationForm(
  _ request: Request,
  context: SwanHTTPRequestContext,
  requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws
  -> OAuthServerRevocationForm
{
  let fields = try await oauthServerForm(
    request, context: context, requestBodyAdmission: requestBodyAdmission)
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

private func oauthServerForm(
  _ request: Request,
  context: SwanHTTPRequestContext,
  requestBodyAdmission: SwanRequestBodyAdmissionConfiguration
) async throws -> [String: String] {
  let body = try await collectAdmittedRequestBody(
    request,
    mediaType: .formURLEncoded,
    admission: requestBodyAdmission.admission,
    policy: requestBodyAdmission.policy,
    maximumBytes: SwanOAuthAuthorizationServerHTTP.maximumFormBytes,
    termination: context.jsonWriteBodyTermination
  )
  defer { withExtendedLifetime(body) {} }
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

/// Stage A — the remote authorization server's wire tokenizer.
///
/// Delegates to the one tokenizer shared with the localhost bridge (§6.3 stages
/// A / A′) so the two cannot drift apart again: the same RFC 6749 §3.3 charset
/// (`$0 > 0x20 && $0 < 0x7F` admitted `"` and `\`), the same 1024-byte per-token
/// and 8192-byte whole-request RAW-INPUT budget in place of this path's 256, and
/// the literal `openid` rejection.
///
/// The thrown error is deliberately NOT collapsed into
/// `OAuthServerRequestError.malformed`: `openid` must surface as
/// `invalid_scope`, not `invalid_request` (§4.8).
private func oauthServerScopes(_ raw: String) throws -> Set<String> {
  try OAuthScopeTokenizer.tokenize(raw)
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

/// §5.7.5's "every entry dropped → empty expansion" row: **not** an error, and
/// **not** silent either.
///
/// A permission set that resolves and expands to zero grants is indistinguishable
/// from success on the wire — the client asked for it, the request succeeded, and
/// the token carries nothing derived from it. `.warn` is the level because an
/// operator seeing this repeatedly is looking at either a permission set written
/// against a different AS's families or an authority gate rejecting every entry,
/// and both are worth acting on. The consent renderer carries the other half
/// (`emptyPermissionSets`), because this log never reaches the person
/// authorizing.
private func oauthServerLogEmptyExpansions(
  _ nsids: [String],
  context: SwanHTTPRequestContext,
  stage: String
) {
  guard !nsids.isEmpty else { return }
  context.logger.warning(
    "oauth permission set expanded to no capabilities",
    metadata: [
      "stage": .string(stage),
      "nsids": .string(nsids.joined(separator: ",")),
    ])
}

private func oauthServerMFAChallengePage(csrf: String, handle: String, factor: SwanAccountPortalMutation, nonce: String) -> String {
  let factorID = factor.factorID ?? ""
  let challenge = factor.challenge ?? ""
  let kind = factor.factorKind ?? (factor.challenge == nil ? .totp : .passkey)
  let passkey = kind == .passkey
  let recovery = kind == .recoveryCode
  let proof: String
  if passkey {
    // The inline script carries the same per-response nonce the CSP
    // `script-src 'nonce-…'` allows, so the ceremony executes under the
    // strict policy instead of being blocked by `default-src 'none'`.
    proof = "<input type=\"hidden\" name=\"challenge\" id=\"swan-challenge\" value=\"\(SwanBrowserPages.escape(challenge))\"><input type=\"hidden\" name=\"clientDataJSON\" id=\"swan-client-data\"><input type=\"hidden\" name=\"authenticatorData\" id=\"swan-auth-data\"><input type=\"hidden\" name=\"credentialID\" id=\"swan-credential\"><input type=\"hidden\" name=\"signature\" id=\"swan-signature\"><script nonce=\"\(SwanBrowserPages.escape(nonce))\">(async()=>{const f=document.forms[0],b=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(s.length/4)*4,'=')),c=>c.charCodeAt(0)),e=a=>{let s='';new Uint8Array(a).forEach(c=>s+=String.fromCharCode(c));return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')};try{const c=await navigator.credentials.get({publicKey:{challenge:b(document.getElementById('swan-challenge').value),rp:{id:location.hostname},user:{id:b('swan-user'),name:'Swan',displayName:'Swan'},pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],timeout:300000,authenticatorSelection:{userVerification:'preferred'},allowCredentials:[]}});document.getElementById('swan-client-data').value=e(c.response.clientDataJSON);document.getElementById('swan-auth-data').value=e(c.response.authenticatorData);document.getElementById('swan-credential').value=e(c.response.rawId);document.getElementById('swan-signature').value=e(c.response.signature);f.submit()}catch(err){document.getElementById('swan-auth-data').value='error:'+err.name}})();</script>"
  } else if recovery {
    proof = "<label>Recovery code <input name=\"code\" autocomplete=\"one-time-code\" required></label>"
  } else {
    proof = "<label>One-time code <input name=\"code\" autocomplete=\"one-time-code\" required></label>"
  }
  return "<!doctype html><html><head><meta charset=\"utf-8\"><title>Swan factor verification</title></head><body><main><h1>Verify your factor</h1><form method=\"post\" action=\"/oauth/authorize/mfa\"><input type=\"hidden\" name=\"csrf\" value=\"\(SwanBrowserPages.escape(csrf))\"><input type=\"hidden\" name=\"handle\" value=\"\(SwanBrowserPages.escape(handle))\"><input type=\"hidden\" name=\"kind\" value=\"\(kind.rawValue)\"><input type=\"hidden\" name=\"factorID\" value=\"\(SwanBrowserPages.escape(factorID))\">\(proof)<button type=\"submit\">Verify securely</button></form></main></body></html>"
}

/// Per-response CSP nonce. The value is single-use, unguessable, and only
/// echoed into the exact response that carries it; it is never persisted.
private func oauthServerCSPNonce() -> String {
  var generator = SystemRandomNumberGenerator()
  let bytes = (0 ..< 16).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
  return Data(bytes).base64EncodedString()
    .replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "=", with: "")
}

private func oauthServerHTML(
  _ status: HTTPResponse.Status, _ body: String, setCookie: String? = nil,
  formActionSource: String? = nil, cspNonce: String? = nil
) -> Response {
  var headers = oauthServerBrowserHeaders(
    contentType: "text/html; charset=utf-8", formActionSource: formActionSource,
    nonce: cspNonce)
  if let setCookie { headers[HTTPField.Name("Set-Cookie")!] = setCookie }
  return Response(
    status: status, headers: headers, body: .init(byteBuffer: ByteBuffer(string: body)))
}

/// CSP `form-action` source for a client's already-validated redirect URI.
///
/// The consent form's submission ends in a redirect to the client's redirect
/// URI, which is cross-origin for every real client. WebKit and Blink apply
/// `form-action` to the redirect that *follows* a form submission, so a bare
/// `'self'` silently blocks the navigation carrying the authorization code:
/// the browser stays on the consent page, no request reaches the client, and
/// the flow never completes. The URI here is the one already checked against
/// the client's registered metadata at PAR, so naming its origin grants no
/// trust the request did not already have.
///
/// Returns `nil` rather than a permissive fallback when the URI cannot be
/// reduced to a safe source expression — the caller then emits plain
/// `'self'`, which fails closed exactly as before.
private func oauthServerFormActionSource(_ redirectURI: String) -> String? {
  guard let components = URLComponents(string: redirectURI),
    let rawScheme = components.scheme, !rawScheme.isEmpty
  else { return nil }
  let scheme = rawScheme.lowercased()
  guard
    scheme.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "+-.".contains($0)) })
  else { return nil }
  // Native clients register custom-scheme redirects with no host; a
  // scheme-only source expression is the correct CSP spelling for those.
  guard let host = components.host, !host.isEmpty else { return "\(scheme):" }
  guard
    host.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "-.:[]".contains($0)) })
  else { return nil }
  guard let port = components.port else { return "\(scheme)://\(host)" }
  return "\(scheme)://\(host):\(port)"
}

private func oauthServerRedirect(_ destination: URL, clearCookie: Bool) -> Response {
  var headers = oauthServerBrowserHeaders()
  headers[.location] = destination.absoluteString
  if clearCookie { headers[HTTPField.Name("Set-Cookie")!] = oauthServerExpiredCookie() }
  return Response(status: .found, headers: headers)
}

private func oauthServerAuthorizationError(_ status: HTTPResponse.Status, clearCookie: Bool = false)
  -> Response
{
  var headers = oauthServerBrowserHeaders(contentType: "text/plain; charset=utf-8")
  if clearCookie { headers[HTTPField.Name("Set-Cookie")!] = oauthServerExpiredCookie() }
  return Response(
    status: status, headers: headers,
    body: .init(byteBuffer: ByteBuffer(string: "authorization request rejected")))
}

private func oauthServerBrowserHeaders(
  contentType: String? = nil, formActionSource: String? = nil, nonce: String? = nil
) -> HTTPFields {
  var headers: HTTPFields = [.cacheControl: "no-store"]
  if let contentType { headers[.contentType] = contentType }
  let formAction = formActionSource.map { "'self' \($0)" } ?? "'self'"
  // `style-src` names the hash of the inlined daisyUI stylesheet, so styled
  // pages keep `default-src 'none'` with no `'unsafe-inline'` and no external
  // style origin.
  var policy = "default-src 'none'; style-src \(SwanBrowserPages.browserStyleCSPSource); "
    + "form-action \(formAction); frame-ancestors 'none'; base-uri 'none'"
  // A per-response nonce admits exactly the inline ceremony script in the
  // page that carries it. The policy is never widened with `unsafe-inline`.
  if let nonce, !nonce.isEmpty {
    policy = "default-src 'none'; script-src 'nonce-\(nonce)'; "
      + "style-src \(SwanBrowserPages.browserStyleCSPSource); "
      + "form-action \(formAction); frame-ancestors 'none'; base-uri 'none'"
  }
  headers[HTTPField.Name("Content-Security-Policy")!] = policy
  headers[HTTPField.Name("X-Frame-Options")!] = "DENY"
  headers[HTTPField.Name("Referrer-Policy")!] = "no-referrer"
  headers[HTTPField.Name("X-Content-Type-Options")!] = "nosniff"
  return headers
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

private func oauthServerBodyFailurePAR(
  _ failure: SwanRequestBodyCollectionFailure
) -> Response {
  switch failure {
  case .unavailable:
    oauthServerPARJSON(
      .serviceUnavailable,
      OAuthServerPARError(error: "temporarily_unavailable")
    )
  case .payloadTooLarge:
    oauthServerPARJSON(.contentTooLarge, OAuthServerPARError(error: "invalid_request"))
  case .invalidRequest:
    oauthServerPARJSON(.badRequest, OAuthServerPARError(error: "invalid_request"))
  }
}

private func oauthServerBodyFailureToken(
  _ failure: SwanRequestBodyCollectionFailure
) -> Response {
  switch failure {
  case .unavailable:
    oauthServerTokenJSON(
      .serviceUnavailable,
      OAuthServerTokenError(error: "temporarily_unavailable")
    )
  case .payloadTooLarge:
    oauthServerTokenJSON(.contentTooLarge, OAuthServerTokenError(error: "invalid_request"))
  case .invalidRequest:
    oauthServerTokenJSON(.badRequest, OAuthServerTokenError(error: "invalid_request"))
  }
}

private func oauthServerJSON<Body: Encodable>(
  _ status: HTTPResponse.Status, _ body: Body, headers: HTTPFields? = nil
) -> Response {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  let data = (try? encoder.encode(body)) ?? Data("{}".utf8)
  var responseHeaders = headers ?? [.contentType: "application/json", .cacheControl: "no-store"]
  if responseHeaders[.contentType] == nil { responseHeaders[.contentType] = "application/json" }
  if responseHeaders[.cacheControl] == nil { responseHeaders[.cacheControl] = "no-store" }
  oauthAPICORSHeaders(&responseHeaders)
  return Response(
    status: status, headers: responseHeaders, body: .init(byteBuffer: ByteBuffer(data: data)))
}
