import Crypto
import Foundation
import HTTPTypes
import Hummingbird
import HummingbirdTesting
import Logging
import NIOCore
import SwanAccounts
import SwanSQLite
import XCTest

@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth

/// HTTP-level coverage for the complete (non-localhost) server assembly. The
/// resolver and transport are deliberately in-process fixtures: no test can
/// turn a CI run into an external metadata fetch.
final class RemoteOAuthAuthorizationServerHTTPTests: XCTestCase, @unchecked Sendable {
  private let issuer = URL(string: "https://swan.example")!
  private let clientID = URL(string: "https://client.example/metadata")!
  private let redirectURI = URL(string: "https://client.example/callback")!
  private let did = "did:plc:abcdefghijklmnopqrstuvwx"
  private let handle = "alice.swan.test"
  private let password = "correct horse battery staple"

  func testRemotePublicPARBrowserTokenRefreshRevocationAndPublication() async throws {
    let metadata = try publicMetadata()
    let fixture = try await makeFixture(metadata: metadata)
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let dpopKey = P256.Signing.PrivateKey()
    let dpopJWK = try jwk(dpopKey)
    let verifier = "remote-oauth-server-test-verifier-000000000000000000"
    let challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString()
    let parForm = form([
      ("client_id", clientID.absoluteString), ("redirect_uri", redirectURI.absoluteString),
      ("response_type", "code"), ("scope", "atproto"), ("state", "remote-state"),
      ("code_challenge", challenge), ("code_challenge_method", "S256"),
    ])
    do {
      let app = fixture.server.buildApplication(
        logger: Logger(label: "RemoteOAuthAuthorizationServerHTTPTests.public"))
      try await app.test(.router) { client in
        for path in [
          "/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server",
        ] {
          try await client.execute(uri: path, method: .get) { response in
            XCTAssertEqual(response.status, .ok)
            XCTAssertEqual(response.headers[.cacheControl], "no-store")
            let object = try self.json(response.body)
            XCTAssertFalse(object.isEmpty)
            if path == "/.well-known/oauth-authorization-server" {
              XCTAssertEqual(
                object["authorization_response_iss_parameter_supported"] as? Bool, true)
              XCTAssertEqual(object["require_pushed_authorization_requests"] as? Bool, true)
              XCTAssertEqual(object["client_id_metadata_document_supported"] as? Bool, true)
              XCTAssertEqual(
                object["token_endpoint_auth_signing_alg_values_supported"] as? [String], ["ES256"])
              XCTAssertEqual(object["scopes_supported"] as? [String], ["atproto"])
            }
          }
        }
        var parNonce: String?
        try await client.execute(
          uri: "/oauth/par", method: .post, headers: formHeaders(),
          body: ByteBuffer(string: parForm)
        ) { response in
          XCTAssertEqual(response.status, .badRequest)
          XCTAssertEqual(try self.error(response.body), "use_dpop_nonce")
          parNonce = response.headers[dpopNonceHeader]
        }
        let parProof = try self.dpop(
          dpopKey, dpopJWK, jti: "remote-public-par", nonce: try XCTUnwrap(parNonce),
          target: try OAuthDPoPProofValidator.normalizedTarget(
            self.issuer.appending(path: "oauth/par"))
        )
        var requestURI: String?
        try await client.execute(
          uri: "/oauth/par", method: .post, headers: formHeaders(dpop: parProof),
          body: ByteBuffer(string: parForm)
        ) { response in
          XCTAssertEqual(response.status, .created)
          let object = try self.json(response.body)
          requestURI = object["request_uri"] as? String
          XCTAssertEqual(object["expires_in"] as? Int, 90)
        }
        let authorize =
          "/oauth/authorize?client_id=\(encode(self.clientID.absoluteString))&request_uri=\(encode(try XCTUnwrap(requestURI)))"
        var firstCookie: String?
        var firstCSRF: String?
        try await client.execute(uri: authorize, method: .get) { response in
          XCTAssertEqual(response.status, .ok)
          firstCookie = self.cookie(response.headers[setCookieHeader])
          firstCSRF = try fixture.runtime.browserSessionService.verify(try XCTUnwrap(firstCookie))
            .csrfToken
        }
        var secondCookie: String?
        var secondCSRF: String?
        try await client.execute(
          uri: "/oauth/authorize", method: .post,
          headers: formHeaders(cookie: try XCTUnwrap(firstCookie)),
          body: ByteBuffer(
            string: self.form([
              ("csrf", try XCTUnwrap(firstCSRF)), ("handle", self.handle),
              ("password", self.password),
            ]))
        ) { response in
          XCTAssertEqual(response.status, .ok)
          secondCookie = self.cookie(response.headers[setCookieHeader])
          secondCSRF = try fixture.runtime.browserSessionService.verify(try XCTUnwrap(secondCookie))
            .csrfToken
        }
        var code: String?
        try await client.execute(
          uri: "/oauth/authorize/consent", method: .post,
          headers: formHeaders(cookie: try XCTUnwrap(secondCookie)),
          body: ByteBuffer(
            string: self.form([("csrf", try XCTUnwrap(secondCSRF)), ("decision", "approve")]))
        ) { response in
          XCTAssertEqual(response.status, .found)
          let destination = try XCTUnwrap(
            URLComponents(string: try XCTUnwrap(response.headers[.location])))
          XCTAssertEqual(destination.scheme, "https")
          XCTAssertEqual(destination.host, "client.example")
          let values = Dictionary(
            uniqueKeysWithValues: (destination.queryItems ?? []).compactMap { item in
              item.value.map { (item.name, $0) }
          })
          XCTAssertEqual(values["state"], "remote-state")
          XCTAssertEqual(values["iss"], self.issuer.absoluteString)
          code = values["code"]
        }
        let codeForm = self.form([
          ("grant_type", "authorization_code"), ("client_id", self.clientID.absoluteString),
          ("redirect_uri", self.redirectURI.absoluteString), ("code", try XCTUnwrap(code)),
          ("code_verifier", verifier),
        ])
        var tokenNonce: String?
        try await client.execute(
          uri: "/oauth/token", method: .post, headers: formHeaders(),
          body: ByteBuffer(string: codeForm)
        ) { response in
          XCTAssertEqual(response.status, .badRequest)
          XCTAssertEqual(try self.error(response.body), "use_dpop_nonce")
          tokenNonce = response.headers[dpopNonceHeader]
        }
        let tokenTarget = try OAuthDPoPProofValidator.normalizedTarget(
          self.issuer.appending(path: "oauth/token"))
        let wrongRedirectForm = self.form([
          ("grant_type", "authorization_code"), ("client_id", self.clientID.absoluteString),
          ("redirect_uri", "https://client.example/other"), ("code", try XCTUnwrap(code)),
          ("code_verifier", verifier),
        ])
        let wrongRedirectProof = try self.dpop(
          dpopKey, dpopJWK, jti: "remote-public-wrong-redirect", nonce: try XCTUnwrap(tokenNonce),
          target: tokenTarget)
        try await client.execute(
          uri: "/oauth/token", method: .post, headers: formHeaders(dpop: wrongRedirectProof),
          body: ByteBuffer(string: wrongRedirectForm)
        ) { response in
          XCTAssertEqual(response.status, .badRequest)
          XCTAssertEqual(try self.error(response.body), "invalid_grant")
        }
        let codeProof = try self.dpop(
          dpopKey, dpopJWK, jti: "remote-public-code", nonce: try XCTUnwrap(tokenNonce),
          target: tokenTarget)
        var accessToken: String?
        var refreshToken: String?
        try await client.execute(
          uri: "/oauth/token", method: .post, headers: formHeaders(dpop: codeProof),
          body: ByteBuffer(string: codeForm)
        ) { response in
          XCTAssertEqual(response.status, .ok)
          let object = try self.json(response.body)
          XCTAssertEqual(object["token_type"] as? String, "DPoP")
          XCTAssertEqual(object["scope"] as? String, "atproto")
          XCTAssertEqual(object["sub"] as? String, self.did)
          accessToken = object["access_token"] as? String
          refreshToken = object["refresh_token"] as? String
          XCTAssertEqual(accessToken?.utf8.count, 43)
          XCTAssertEqual(refreshToken?.utf8.count, 43)
          XCTAssertFalse(Data(buffer: response.body).description.contains(self.password))
        }
        let originalRefresh = try XCTUnwrap(refreshToken)
        let refreshForm = self.form([
          ("grant_type", "refresh_token"), ("client_id", self.clientID.absoluteString),
          ("refresh_token", originalRefresh),
        ])
        let refreshProof = try self.dpop(
          dpopKey, dpopJWK, jti: "remote-public-refresh", nonce: try XCTUnwrap(tokenNonce),
          target: tokenTarget)
        var rotatedRefresh: String?
        try await client.execute(
          uri: "/oauth/token", method: .post, headers: formHeaders(dpop: refreshProof),
          body: ByteBuffer(string: refreshForm)
        ) { response in
          XCTAssertEqual(response.status, .ok)
          rotatedRefresh = try self.json(response.body)["refresh_token"] as? String
          XCTAssertNotEqual(rotatedRefresh, originalRefresh)
        }
        let reuseProof = try self.dpop(
          dpopKey, dpopJWK, jti: "remote-public-reuse", nonce: try XCTUnwrap(tokenNonce),
          target: tokenTarget)
        try await client.execute(
          uri: "/oauth/token", method: .post, headers: formHeaders(dpop: reuseProof),
          body: ByteBuffer(string: refreshForm)
        ) { response in
          XCTAssertEqual(response.status, .badRequest)
          XCTAssertEqual(try self.error(response.body), "invalid_grant")
        }
        let revokeForm = self.form([
          ("token", try XCTUnwrap(accessToken)), ("client_id", self.clientID.absoluteString),
          ("token_type_hint", "access_token"),
        ])
        let revokeProof = try self.dpop(
          dpopKey, dpopJWK, jti: "remote-public-revoke", nonce: try XCTUnwrap(tokenNonce),
          target: try OAuthDPoPProofValidator.normalizedTarget(
            self.issuer.appending(path: "oauth/revoke"))
        )
        try await client.execute(
          uri: "/oauth/revoke", method: .post, headers: formHeaders(dpop: revokeProof),
          body: ByteBuffer(string: revokeForm)
        ) { response in
          XCTAssertEqual(response.status, .ok)
          XCTAssertEqual(response.headers[.cacheControl], "no-store")
        }
      }
      try await fixture.control.close()
    } catch {
      try? await fixture.control.close()
      throw error
    }
  }

  func testOAuthBrowserCORSIsNarrowAndNeverCredentialed() async throws {
    let fixture = try await makeFixture(metadata: try publicMetadata())
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let origin = HTTPField.Name("Origin")!
    let allowOrigin = HTTPField.Name("Access-Control-Allow-Origin")!
    let allowMethods = HTTPField.Name("Access-Control-Allow-Methods")!
    let allowHeaders = HTTPField.Name("Access-Control-Allow-Headers")!
    let exposeHeaders = HTTPField.Name("Access-Control-Expose-Headers")!
    let allowCredentials = HTTPField.Name("Access-Control-Allow-Credentials")!
    var mutableBrowserHeaders: HTTPFields = [:]
    mutableBrowserHeaders[origin] = "https://browser.example"
    let browserHeaders = mutableBrowserHeaders
    do {
      let app = fixture.server.buildApplication(
        logger: Logger(label: "RemoteOAuthAuthorizationServerHTTPTests.cors"))
      try await app.test(.router) { client in
        for path in [
          "/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server",
        ] {
          try await client.execute(uri: path, method: .get, headers: browserHeaders) { response in
            XCTAssertEqual(response.status, .ok)
            XCTAssertEqual(response.headers[allowOrigin], "*")
            XCTAssertEqual(response.headers[allowMethods], "GET, OPTIONS")
            XCTAssertEqual(response.headers[allowHeaders], "Content-Type, DPoP")
            XCTAssertNil(response.headers[allowCredentials])
          }
          try await client.execute(uri: path, method: .options, headers: browserHeaders) { response in
            XCTAssertEqual(response.status, .noContent)
            XCTAssertEqual(response.headers[allowOrigin], "*")
            XCTAssertEqual(response.headers[allowMethods], "GET, OPTIONS")
            XCTAssertEqual(response.headers[allowHeaders], "Content-Type, DPoP")
            XCTAssertNil(response.headers[allowCredentials])
          }
        }
        for path in ["/oauth/par", "/oauth/token", "/oauth/revoke"] {
          try await client.execute(uri: path, method: .options, headers: browserHeaders) { response in
            XCTAssertEqual(response.status, .noContent)
            XCTAssertEqual(response.headers[allowOrigin], "*")
            XCTAssertEqual(response.headers[allowMethods], "POST, OPTIONS")
            XCTAssertEqual(response.headers[allowHeaders], "Content-Type, DPoP")
            XCTAssertEqual(response.headers[exposeHeaders], "DPoP-Nonce, WWW-Authenticate")
            XCTAssertNil(response.headers[allowCredentials])
          }
        }
        try await client.execute(uri: "/oauth/par", method: .post, headers: browserHeaders) { response in
          XCTAssertEqual(response.status, .badRequest)
          XCTAssertEqual(response.headers[allowOrigin], "*")
          XCTAssertEqual(response.headers[exposeHeaders], "DPoP-Nonce, WWW-Authenticate")
          XCTAssertNil(response.headers[allowCredentials])
        }
      }
      try await fixture.control.close()
    } catch {
      try? await fixture.control.close()
      throw error
    }
  }

  func testOAuthMetadataRequiresOriginIssuerAndAtprotoScope() throws {
    for value in [
      "https://swan.example/oauth",
      "https://swan.example/?query=1",
      "https://swan.example/#fragment",
      "https://operator@swan.example",
    ] {
      XCTAssertThrowsError(try OAuthAuthorizationServerMetadata(issuer: try XCTUnwrap(URL(string: value))))
    }
    let metadata = try OAuthAuthorizationServerMetadata(
      issuer: issuer, scopesSupported: ["atproto", "space:did:plc:alice"])
    XCTAssertEqual(metadata.scopesSupported, ["atproto", "space:did:plc:alice"])
    XCTAssertThrowsError(try OAuthAuthorizationServerMetadata(issuer: issuer, scopesSupported: ["space:read"]))
    XCTAssertThrowsError(try OAuthProtectedResourceMetadata(
      resource: issuer,
      authorizationServer: URL(string: "https://swan.example/oauth")!
    ))
  }

  func testConfidentialPAREnforcesIssuerAudienceAndAssertionReplay() async throws {
    let clientKey = P256.Signing.PrivateKey()
    let clientJWK = try jwk(clientKey, keyID: "client-key")
    let metadata = try OAuthClientMetadata(
      clientID: clientID,
      redirectURIs: [redirectURI],
      grantTypes: ["authorization_code", "refresh_token"],
      responseTypes: ["code"],
      scopes: ["atproto"],
      tokenEndpointAuthMethod: .privateKeyJWT,
      tokenEndpointAuthSigningAlgorithm: "ES256",
      dpopBoundAccessTokens: true,
      jwks: try OAuthJSONWebKeySet(keys: [clientJWK])
    )
    let fixture = try await makeFixture(metadata: metadata)
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let dpopKey = P256.Signing.PrivateKey()
    let dpopJWK = try jwk(dpopKey)
    let challenge = String(repeating: "a", count: 43)
    let audience = issuer.absoluteString
    do {
      let app = fixture.server.buildApplication(
        logger: Logger(label: "RemoteOAuthAuthorizationServerHTTPTests.confidential"))
      try await app.test(.router) { client in
        var nonce: String?
        let bare = self.parForm(challenge: challenge, assertion: nil)
        try await client.execute(
          uri: "/oauth/par", method: .post, headers: formHeaders(), body: ByteBuffer(string: bare)
        ) { response in
          XCTAssertEqual(response.status, .badRequest)
          nonce = response.headers[dpopNonceHeader]
        }
        let target = try OAuthDPoPProofValidator.normalizedTarget(
          self.issuer.appending(path: "oauth/par"))
        let wrongAudience = try self.clientAssertion(
          clientKey, keyID: "client-key", audience: self.issuer.appending(path: "oauth/token").absoluteString,
          jti: "wrong-audience")
        let badProof = try self.dpop(
          dpopKey, dpopJWK, jti: "conf-bad-aud", nonce: try XCTUnwrap(nonce), target: target)
        try await client.execute(
          uri: "/oauth/par", method: .post, headers: formHeaders(dpop: badProof),
          body: ByteBuffer(string: self.parForm(challenge: challenge, assertion: wrongAudience))
        ) { response in
          XCTAssertEqual(response.status, .badRequest)
          XCTAssertEqual(try self.error(response.body), "invalid_request")
        }
        let validAssertion = try self.clientAssertion(
          clientKey, keyID: "client-key", audience: audience, jti: "valid-assertion")
        let validProof = try self.dpop(
          dpopKey, dpopJWK, jti: "conf-valid", nonce: try XCTUnwrap(nonce), target: target)
        try await client.execute(
          uri: "/oauth/par", method: .post, headers: formHeaders(dpop: validProof),
          body: ByteBuffer(string: self.parForm(challenge: challenge, assertion: validAssertion))
        ) { response in
          XCTAssertEqual(response.status, .created)
        }
        let replayProof = try self.dpop(
          dpopKey, dpopJWK, jti: "conf-replay", nonce: try XCTUnwrap(nonce), target: target)
        try await client.execute(
          uri: "/oauth/par", method: .post, headers: formHeaders(dpop: replayProof),
          body: ByteBuffer(string: self.parForm(challenge: challenge, assertion: validAssertion))
        ) { response in
          XCTAssertEqual(response.status, .badRequest)
          XCTAssertEqual(try self.error(response.body), "invalid_request")
        }
      }
      try await fixture.control.close()
    } catch {
      try? await fixture.control.close()
      throw error
    }
  }

  func testUnsafeRemoteMetadataNeverActivatesAClientOrContactsTransport() async throws {
    let metadata = try publicMetadata()
    let privateIP = try XCTUnwrap(OAuthIPAddress(literal: "10.0.0.8"))
    let fixture = try await makeFixture(metadata: metadata, resolverAnswers: [[privateIP]])
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let key = P256.Signing.PrivateKey()
    let publicJWK = try jwk(key)
    let form = parForm(challenge: String(repeating: "a", count: 43), assertion: nil)
    do {
      let app = fixture.server.buildApplication(
        logger: Logger(label: "RemoteOAuthAuthorizationServerHTTPTests.ssrf"))
      try await app.test(.router) { client in
        var nonce: String?
        try await client.execute(
          uri: "/oauth/par", method: .post, headers: formHeaders(), body: ByteBuffer(string: form)
        ) { response in
          nonce = response.headers[dpopNonceHeader]
        }
        let proof = try self.dpop(
          key, publicJWK, jti: "unsafe-metadata", nonce: try XCTUnwrap(nonce),
          target: try OAuthDPoPProofValidator.normalizedTarget(
            self.issuer.appending(path: "oauth/par")))
        try await client.execute(
          uri: "/oauth/par", method: .post, headers: formHeaders(dpop: proof),
          body: ByteBuffer(string: form)
        ) { response in
          XCTAssertEqual(response.status, .badRequest)
          XCTAssertEqual(try self.error(response.body), "invalid_request")
        }
      }
      let requestCount = await fixture.transport.requestCount()
      XCTAssertEqual(requestCount, 0)
      try await fixture.control.close()
    } catch {
      try? await fixture.control.close()
      throw error
    }
  }

  func testDeactivatedAccountCannotCompleteRemoteAuthorization() async throws {
    let fixture = try await makeFixture(metadata: try publicMetadata())
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let key = P256.Signing.PrivateKey()
    let publicJWK = try jwk(key)
    let verifier = "deactivated-oauth-server-test-verifier-00000000000000"
    let challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString()
    let par = form([
      ("client_id", clientID.absoluteString), ("redirect_uri", redirectURI.absoluteString),
      ("response_type", "code"), ("scope", "atproto"), ("state", "deactivated-state"),
      ("code_challenge", challenge), ("code_challenge_method", "S256"),
    ])
    do {
      let app = fixture.server.buildApplication(
        logger: Logger(label: "RemoteOAuthAuthorizationServerHTTPTests.deactivated"))
      try await app.test(.router) { client in
        var nonce: String?
        try await client.execute(
          uri: "/oauth/par", method: .post, headers: formHeaders(), body: ByteBuffer(string: par)
        ) { response in
          XCTAssertEqual(response.status, .badRequest)
          nonce = response.headers[dpopNonceHeader]
        }
        let proof = try self.dpop(
          key, publicJWK, jti: "deactivated-par", nonce: try XCTUnwrap(nonce),
          target: try OAuthDPoPProofValidator.normalizedTarget(
            self.issuer.appending(path: "oauth/par"))
        )
        var requestURI: String?
        try await client.execute(
          uri: "/oauth/par", method: .post, headers: formHeaders(dpop: proof),
          body: ByteBuffer(string: par)
        ) { response in
          XCTAssertEqual(response.status, .created)
          requestURI = try self.json(response.body)["request_uri"] as? String
        }
        let authorize =
          "/oauth/authorize?client_id=\(encode(self.clientID.absoluteString))&request_uri=\(encode(try XCTUnwrap(requestURI)))"
        var cookie: String?
        var csrf: String?
        try await client.execute(uri: authorize, method: .get) { response in
          XCTAssertEqual(response.status, .ok)
          cookie = self.cookie(response.headers[setCookieHeader])
          csrf = try fixture.runtime.browserSessionService.verify(try XCTUnwrap(cookie)).csrfToken
        }
        _ = try await fixture.accounts.transitionStatus(did: self.did, to: .deactivated)
        try await client.execute(
          uri: "/oauth/authorize", method: .post,
          headers: formHeaders(cookie: try XCTUnwrap(cookie)),
          body: ByteBuffer(
            string: self.form([
              ("csrf", try XCTUnwrap(csrf)), ("handle", self.handle), ("password", self.password),
            ]))
        ) { response in
          XCTAssertEqual(response.status, .unauthorized)
          XCTAssertFalse(Data(buffer: response.body).description.contains(self.password))
        }
      }
      try await fixture.control.close()
    } catch {
      try? await fixture.control.close()
      throw error
    }
  }

  func testAuthorizationDenialRedirectIncludesIssuer() async throws {
    let fixture = try await makeFixture(metadata: try publicMetadata())
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    do {
      let resolved = try await fixture.completeConfiguration.clientMetadataLoader.load(clientID: clientID)
      let session = try OAuthValidatedSession(
        issuer: issuer.absoluteString, client: resolved, redirectURI: redirectURI, scopes: ["atproto"],
        dpopProof: .init(
          keyThumbprint: String(repeating: "n", count: 43), jwtID: "denial-contract",
          issuedAt: Date())
      )
      let requestURI = try await fixture.runtime.tokenService.createPushedAuthorizationRequest(
        session: session, state: "denied-state", codeChallengeS256: String(repeating: "a", count: 43))
      let browser = try fixture.runtime.browserSessionService.issue(
        requestURI: requestURI, subject: did, lifetime: 300)
      let app = fixture.server.buildApplication(
        logger: Logger(label: "RemoteOAuthAuthorizationServerHTTPTests.denial"))
      try await app.test(.router) { client in
        try await client.execute(
          uri: "/oauth/authorize/consent", method: .post,
          headers: formHeaders(cookie: browser.value),
          body: ByteBuffer(string: self.form([
            ("csrf", browser.session.csrfToken), ("decision", "deny"),
          ]))
        ) { response in
          XCTAssertEqual(response.status, .found)
          let components = try XCTUnwrap(
            URLComponents(string: try XCTUnwrap(response.headers[.location])))
          let values = Dictionary(
            uniqueKeysWithValues: (components.queryItems ?? []).compactMap { item in
              item.value.map { (item.name, $0) }
            })
          XCTAssertEqual(values["error"], "access_denied")
          XCTAssertEqual(values["state"], "denied-state")
          XCTAssertEqual(values["iss"], self.issuer.absoluteString)
        }
      }
      try await fixture.control.close()
    } catch {
      try? await fixture.control.close()
      throw error
    }
  }

  func testCompleteOAuthNeverPublishesWhenServerIdentityMismatches() async throws {
    let fixture = try await makeFixture(metadata: try publicMetadata())
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let profile = try ProtocolProfile.load(
      from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
    )
    let mismatched = SwanHTTPServer(
      profile: profile,
      configuration: .init(
        host: "127.0.0.1", port: 3_000, publicURL: URL(string: "https://other.swan.example")!),
      oauthRuntime: fixture.runtime,
      authorizationServerConfiguration: fixture.completeConfiguration
    )
    do {
      let app = mismatched.buildApplication(
        logger: Logger(label: "RemoteOAuthAuthorizationServerHTTPTests.mismatch"))
      try await app.test(.router) { client in
        for path in [
          "/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server",
          "/oauth/authorize",
        ] {
          try await client.execute(uri: path, method: .get) { response in
            XCTAssertEqual(response.status, .serviceUnavailable, path)
          }
        }
        for path in ["/oauth/par", "/oauth/token", "/oauth/revoke"] {
          try await client.execute(uri: path, method: .post) { response in
            XCTAssertEqual(response.status, .notFound, path)
          }
        }
      }
      try await fixture.control.close()
    } catch {
      try? await fixture.control.close()
      throw error
    }
  }

  private func makeFixture(
    metadata: OAuthClientMetadata,
    resolverAnswers: [[OAuthIPAddress]]? = nil
  ) async throws -> Fixture {
    let root = FileManager.default.temporaryDirectory.appending(
      path: "RemoteOAuthAuthorizationServerHTTPTests-\(UUID().uuidString)")
    let control = try await SQLiteControlDatabase(dataDirectory: root)
    do {
      let hasher = try LibsodiumArgon2idHasher(policy: .interactive)
      let accounts = DurableAccountDirectory(
        store: control, passwordHasher: hasher,
        verificationExecutor: try Argon2idVerificationExecutor(hasher: hasher))
      _ = try await accounts.registerProvisionedAccount(
        did: did, canonicalHandle: handle, password: password,
        signingReference: try AccountKeyReference(
          accountDID: did, purpose: .signing, generation: 1),
        rotationReference: try AccountKeyReference(
          accountDID: did, purpose: .rotation, generation: 1)
      )
      let publicIP = try XCTUnwrap(OAuthIPAddress(literal: "93.184.216.34"))
      let resolver = RemoteOAuthResolver(
        answers: resolverAnswers ?? Array(repeating: [publicIP], count: 64))
      let body = try JSONEncoder().encode(metadata)
      let transport = RemoteOAuthTransport(
        response: .init(
          status: 200, headers: ["content-type": ["application/json"]], body: body,
          responseURL: clientID, connectedPeerAddress: publicIP))
      let loader = try OAuthClientMetadataLoader(
        fetcher: .init(
          policy: try OAuthRemoteFetchPolicy(), resolver: resolver, transport: transport),
        controlStore: control
      )
      let runtime = try SwanOAuthRuntime(
        controlStore: control, serverKey: Data(repeating: 0xE2, count: 32))
      let complete = try SwanOAuthAuthorizationServerConfiguration(
        issuer: issuer, protectedResource: issuer, accounts: accounts, clientMetadataLoader: loader)
      let profile = try ProtocolProfile.load(
        from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json"))
      let server = SwanHTTPServer(
        profile: profile, configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: issuer),
        oauthRuntime: runtime, authorizationServerConfiguration: complete)
      return .init(
        server: server,
        runtime: runtime,
        accounts: accounts,
        completeConfiguration: complete,
        control: control,
        root: root,
        transport: transport
      )
    } catch {
      try? await control.close()
      throw error
    }
  }

  private func publicMetadata() throws -> OAuthClientMetadata {
    try OAuthClientMetadata(
      clientID: clientID, redirectURIs: [redirectURI],
      grantTypes: ["authorization_code", "refresh_token"], responseTypes: ["code"],
      scopes: ["atproto"], dpopBoundAccessTokens: true)
  }

  private func parForm(challenge: String, assertion: String?) -> String {
    var values = [
      ("client_id", clientID.absoluteString), ("redirect_uri", redirectURI.absoluteString),
      ("response_type", "code"), ("scope", "atproto"), ("state", "state"),
      ("code_challenge", challenge), ("code_challenge_method", "S256"),
    ]
    if let assertion {
      values += [
        ("client_assertion_type", OAuthClientAssertionValidator.assertionType),
        ("client_assertion", assertion),
      ]
    }
    return form(values)
  }

  private func form(_ values: [(String, String)]) -> String {
    values.map { "\(encode($0.0))=\(encode($0.1))" }.joined(separator: "&")
  }

  private func formHeaders(dpop: String? = nil, cookie: String? = nil) -> HTTPFields {
    var headers: HTTPFields = [.contentType: "application/x-www-form-urlencoded"]
    if let dpop { headers[dpopHeader] = dpop }
    if let cookie { headers[.cookie] = "__Host-swan-oauth=\(cookie)" }
    return headers
  }

  private func dpop(
    _ key: P256.Signing.PrivateKey, _ publicJWK: OAuthJSONWebKey, jti: String, nonce: String,
    target: String
  ) throws -> String {
    struct Header: Encodable {
      let alg = "ES256"
      let typ = OAuthDPoPProofValidator.proofType
      let jwk: OAuthJSONWebKey
    }
    struct Claims: Encodable {
      let jti: String
      let iat: Int64
      let htm = "POST"
      let htu: String
      let nonce: String
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let header = try encoder.encode(Header(jwk: publicJWK)).base64URLEncodedString()
    let claims = try encoder.encode(
      Claims(jti: jti, iat: Int64(Date().timeIntervalSince1970), htu: target, nonce: nonce)
    ).base64URLEncodedString()
    let input = "\(header).\(claims)"
    return
      "\(input).\(try P256WireSignature.sign(Data(input.utf8), using: key).base64URLEncodedString())"
  }

  private func clientAssertion(
    _ key: P256.Signing.PrivateKey, keyID: String, audience: String, jti: String
  ) throws -> String {
    struct Header: Encodable {
      let alg = "ES256"
      let kid: String
    }
    struct Claims: Encodable {
      let iss: String
      let sub: String
      let aud: String
      let iat: Int64
      let exp: Int64
      let jti: String
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let header = try encoder.encode(Header(kid: keyID)).base64URLEncodedString()
    let now = Int64(Date().timeIntervalSince1970)
    let claims = try encoder.encode(
      Claims(
        iss: clientID.absoluteString, sub: clientID.absoluteString, aud: audience, iat: now,
        exp: now + 120, jti: jti)
    ).base64URLEncodedString()
    let input = "\(header).\(claims)"
    return
      "\(input).\(try P256WireSignature.sign(Data(input.utf8), using: key).base64URLEncodedString())"
  }

  private func jwk(_ key: P256.Signing.PrivateKey, keyID: String? = nil) throws -> OAuthJSONWebKey {
    let representation = key.publicKey.x963Representation
    return try OAuthJSONWebKey(
      x: Data(representation[1..<33]).base64URLEncodedString(),
      y: Data(representation[33..<65]).base64URLEncodedString(), keyID: keyID)
  }

  private func json(_ body: ByteBuffer) throws -> [String: Any] {
    try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: body)) as? [String: Any])
  }
  private func error(_ body: ByteBuffer) throws -> String {
    try XCTUnwrap(try json(body)["error"] as? String)
  }
  private func cookie(_ value: String?) -> String? {
    value?.split(separator: ";", maxSplits: 1).first?.split(separator: "=", maxSplits: 1)
      .dropFirst().first.map(String.init)
  }
  private func packageRoot() -> URL {
    URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent()
  }

  private struct Fixture {
    let server: SwanHTTPServer
    let runtime: SwanOAuthRuntime
    let accounts: DurableAccountDirectory
    let completeConfiguration: SwanOAuthAuthorizationServerConfiguration
    let control: SQLiteControlDatabase
    let root: URL
    let transport: RemoteOAuthTransport
  }
}

private actor RemoteOAuthResolver: OAuthHostnameResolving {
  private var answers: [[OAuthIPAddress]]
  private var index = 0
  init(answers: [[OAuthIPAddress]]) { self.answers = answers }
  func resolve(host _: String) async throws -> [OAuthIPAddress] {
    guard !answers.isEmpty else { throw SwanError.unavailable("missing test DNS response") }
    defer { index += 1 }
    return answers[min(index, answers.count - 1)]
  }
}

private actor RemoteOAuthTransport: OAuthRemoteTransport {
  private let response: OAuthRemoteHTTPResponse
  private var requests = 0
  init(response: OAuthRemoteHTTPResponse) { self.response = response }
  func get(
    url _: URL,
    approvedPeers _: Set<OAuthIPAddress>,
    timeout _: TimeInterval,
    maximumBodyBytes _: Int
  ) async throws
    -> OAuthRemoteHTTPResponse
  {
    requests += 1
    return response
  }
  func requestCount() -> Int { requests }
}

private let dpopHeader = HTTPField.Name("DPoP")!
private let dpopNonceHeader = HTTPField.Name("DPoP-Nonce")!
private let setCookieHeader = HTTPField.Name("Set-Cookie")!

private func encode(_ value: String) -> String {
  value.utf8.map { byte in
    switch byte {
    case 65...90, 97...122, 48...57, 45, 46, 95, 126: String(UnicodeScalar(byte))
    case 32: "+"
    default: String(format: "%%%02X", byte)
    }
  }.joined()
}
