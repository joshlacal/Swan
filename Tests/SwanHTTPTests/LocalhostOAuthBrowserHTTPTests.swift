import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import PetrelCrypto
import SwanAccounts
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite
import SwanStorage
import XCTest

final class LocalhostOAuthBrowserHTTPTests: XCTestCase, @unchecked Sendable {
    private let issuer = URL(string: "https://swan.example")!
    private let clientID = URL(string: "http://localhost?scope=atproto&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback")!
    private let redirectURI = URL(string: "http://127.0.0.1/callback")!
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let handle = "alice.swan.test"
    private let password = "correct horse battery staple"

    func testBrowserPagesAndAuthorizationErrorsSendStrictSecurityHeaders() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let session = try makeSession(
            proofID: "localhost-browser-security-headers",
            keyThumbprint: String(repeating: "h", count: 43)
        )
        let requestURI = try await fixture.runtime.tokenService.createPushedAuthorizationRequest(
            session: session,
            state: "localhost-browser-security-headers",
            codeChallengeS256: String(repeating: "a", count: 43)
        )
        let authorize =
            "/oauth/authorize?client_id=\(formEncode(clientID.absoluteString))&request_uri=\(formEncode(requestURI))"
        do {
            let app = fixture.server.buildApplication(
                logger: Logger(label: "LocalhostOAuthBrowserHTTPTests.browser-headers")
            )
            try await app.test(.router) { client in
                try await client.execute(uri: authorize, method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                    self.assertStrictBrowserSecurityHeaders(
                        response.headers,
                        contentType: "text/html; charset=utf-8"
                    )
                }
                try await client.execute(uri: "/oauth/authorize", method: .get) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    self.assertStrictBrowserSecurityHeaders(
                        response.headers,
                        contentType: "text/plain; charset=utf-8"
                    )
                }
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testTrustedProxyRequiresClientIPBeforeLoginAdmission() async throws {
        let admission = CountingLoginAdmissionStore()
        let policy = try SwanLoginClientIdentityPolicy(
            // Hummingbird's live test listener may accept the loopback client
            // over either family. Both are trusted test peers; the forwarded
            // header is still required for either one.
            trustedProxyPeerLiterals: ["127.0.0.1", "::1"]
        )
        let fixture = try await makeFixture(
            loginClientIdentityPolicy: policy,
            loginAdmissionStore: admission
        )
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let session = try makeSession(
            proofID: "trusted-proxy-missing-client-ip",
            keyThumbprint: String(repeating: "p", count: 43)
        )
        let requestURI = try await fixture.runtime.tokenService
            .createPushedAuthorizationRequest(
                session: session,
                state: "trusted-proxy-missing-client-ip",
                codeChallengeS256: String(repeating: "a", count: 43)
            )
        let authorizeQuery =
            "/oauth/authorize?client_id=\(formEncode(clientID.absoluteString))"
            + "&request_uri=\(formEncode(requestURI))"

        do {
            let app = fixture.server.buildApplication(
                logger: Logger(
                    label: "LocalhostOAuthBrowserHTTPTests.trusted-proxy"
                )
            )
            try await app.test(.live) { client in
                var loginCookie: String?
                var loginCSRF: String?
                try await client.execute(
                    uri: authorizeQuery,
                    method: .get
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    loginCookie = self.cookieValue(
                        try XCTUnwrap(response.headers[setCookieHeader])
                    )
                    loginCSRF = try fixture.runtime.browserSessionService
                        .verify(try XCTUnwrap(loginCookie)).csrfToken
                }
                let form = [
                    ("csrf", try XCTUnwrap(loginCSRF)),
                    ("handle", handle),
                    ("password", password),
                ].map {
                    "\(formEncode($0.0))=\(formEncode($0.1))"
                }.joined(separator: "&")
                try await client.execute(
                    uri: "/oauth/authorize",
                    method: .post,
                    headers: browserFormHeaders(
                        cookie: try XCTUnwrap(loginCookie)
                    ),
                    body: ByteBuffer(string: form)
                ) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                }
            }
            let admissionInvocations = await admission.invocationCount()
            XCTAssertEqual(admissionInvocations, 0)
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testLocalBrowserFlowConsumesPARAndMintsOnePKCEBoundCode() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let verifier = "swan-localhost-browser-test-verifier-000000000000000"
        let challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString()
        let signingKey = P256.Signing.PrivateKey()
        let jwk = try makeJWK(signingKey)
        let originalSession = try makeSession(
            proofID: "browser-original-proof",
            keyThumbprint: jwk.thumbprint()
        )
        let requestURI = try await fixture.runtime.tokenService.createPushedAuthorizationRequest(
            session: originalSession,
            state: "client-return-state",
            codeChallengeS256: challenge
        )
        let authorizeQuery = "/oauth/authorize?client_id=\(formEncode(clientID.absoluteString))&request_uri=\(formEncode(requestURI))"

        do {
            let app = fixture.server.buildApplication(logger: Logger(label: "LocalhostOAuthBrowserHTTPTests"))
            try await app.test(.live) { client in
                var loginCookie: String?
                var loginCSRF: String?
                try await client.execute(uri: authorizeQuery, method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    XCTAssertEqual(response.headers[.contentType], "text/html; charset=utf-8")
                    let cookie = try XCTUnwrap(response.headers[setCookieHeader])
                    XCTAssertTrue(cookie.hasPrefix("__Host-swan-oauth="))
                    XCTAssertTrue(cookie.contains("Secure"))
                    XCTAssertTrue(cookie.contains("HttpOnly"))
                    loginCookie = self.cookieValue(cookie)
                    loginCSRF = try fixture.runtime.browserSessionService.verify(try XCTUnwrap(loginCookie)).csrfToken
                }

                let loginForm = [
                    ("csrf", try XCTUnwrap(loginCSRF)),
                    ("handle", handle),
                    ("password", password),
                ].map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&")
                var consentCookie: String?
                var consentCSRF: String?
                try await client.execute(
                    uri: "/oauth/authorize",
                    method: .post,
                    headers: browserFormHeaders(cookie: try XCTUnwrap(loginCookie)),
                    body: ByteBuffer(string: loginForm)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    let consentHTML = String(
                        decoding: Data(buffer: response.body),
                        as: UTF8.self
                    )
                    XCTAssertTrue(
                        consentHTML.contains(
                            self.clientID.absoluteString
                                .replacingOccurrences(
                                    of: "&",
                                    with: "&amp;"
                                )
                        )
                    )
                    XCTAssertTrue(
                        consentHTML.contains(">atproto</code>")
                    )
                    let cookie = try XCTUnwrap(response.headers[setCookieHeader])
                    consentCookie = self.cookieValue(cookie)
                    let session = try fixture.runtime.browserSessionService.verify(try XCTUnwrap(consentCookie))
                    XCTAssertEqual(session.subject, self.did)
                    XCTAssertNotNil(session.subjectRevisionMicroseconds)
                    consentCSRF = session.csrfToken
                }

                let consentForm = "csrf=\(formEncode(try XCTUnwrap(consentCSRF)))&decision=approve"
                var code: String?
                try await client.execute(
                    uri: "/oauth/authorize/consent",
                    method: .post,
                    headers: browserFormHeaders(cookie: try XCTUnwrap(consentCookie)),
                    body: ByteBuffer(string: consentForm)
                ) { response in
                    XCTAssertEqual(response.status, .found)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    XCTAssertTrue(try XCTUnwrap(response.headers[setCookieHeader]).contains("Max-Age=0"))
                    let redirect = try XCTUnwrap(response.headers[.location])
                    let components = try XCTUnwrap(URLComponents(string: redirect))
                    XCTAssertEqual(components.scheme, "http")
                    XCTAssertEqual(components.host, "127.0.0.1")
                    XCTAssertEqual(components.path, "/callback")
                    let values = Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).compactMap { item in
                        item.value.map { (item.name, $0) }
                    })
                    XCTAssertEqual(values["state"], "client-return-state")
                    XCTAssertEqual(values["iss"], self.issuer.absoluteString)
                    code = values["code"]
                }

                let tokenForm = [
                    ("grant_type", "authorization_code"),
                    ("client_id", clientID.absoluteString),
                    ("redirect_uri", redirectURI.absoluteString),
                    ("code", try XCTUnwrap(code)),
                    ("code_verifier", verifier),
                ].map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&")
                var nonce: String?
                try await client.execute(
                    uri: "/oauth/token",
                    method: .post,
                    headers: tokenHeaders(),
                    body: ByteBuffer(string: tokenForm)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(from: response.body), "use_dpop_nonce")
                    nonce = response.headers[dpopNonceHeader]
                }
                let target = try OAuthDPoPProofValidator.normalizedTarget(issuer.appending(path: "oauth/token"))
                let codeProof = try makeDPoPProof(
                    key: signingKey, jwk: jwk, jti: "browser-code-token", nonce: try XCTUnwrap(nonce), target: target
                )
                var refreshToken: String?
                try await client.execute(
                    uri: "/oauth/token",
                    method: .post,
                    headers: tokenHeaders(dpop: codeProof),
                    body: ByteBuffer(string: tokenForm)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let tokens = try self.tokenResponse(from: response.body)
                    XCTAssertEqual(tokens["token_type"], "DPoP")
                    XCTAssertEqual(tokens["scope"], "atproto")
                    XCTAssertEqual(tokens["sub"], self.did)
                    XCTAssertEqual(tokens["access_token"]?.utf8.count, 43)
                    refreshToken = tokens["refresh_token"]
                }
                let originalRefresh = try XCTUnwrap(refreshToken)
                let refreshForm = [
                    ("grant_type", "refresh_token"),
                    ("client_id", clientID.absoluteString),
                    ("refresh_token", originalRefresh),
                ].map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&")
                let refreshProof = try makeDPoPProof(
                    key: signingKey, jwk: jwk, jti: "browser-refresh-token", nonce: try XCTUnwrap(nonce), target: target
                )
                try await client.execute(
                    uri: "/oauth/token",
                    method: .post,
                    headers: tokenHeaders(dpop: refreshProof),
                    body: ByteBuffer(string: refreshForm)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertNotEqual(try self.tokenResponse(from: response.body)["refresh_token"], originalRefresh)
                }
                let reuseProof = try makeDPoPProof(
                    key: signingKey, jwk: jwk, jti: "browser-refresh-reuse", nonce: try XCTUnwrap(nonce), target: target
                )
                try await client.execute(
                    uri: "/oauth/token",
                    method: .post,
                    headers: tokenHeaders(dpop: reuseProof),
                    body: ByteBuffer(string: refreshForm)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(from: response.body), "invalid_grant")
                }

                // A consumed PAR is not a browser-login replay capability.
                try await client.execute(uri: authorizeQuery, method: .get) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                }
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testLocalOAuthMFAIsAdmittedTwoPhaseAndRendersOperativeWebAuthn() async throws {
        let fixture = try await makeFixture(withTOTP: true)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let requestSession = try makeSession(
            proofID: "localhost-mfa-flow",
            keyThumbprint: String(repeating: "m", count: 43)
        )
        let requestURI = try await fixture.runtime.tokenService.createPushedAuthorizationRequest(
            session: requestSession,
            state: "localhost-mfa-state",
            codeChallengeS256: String(repeating: "a", count: 43)
        )
        let authorize = "/oauth/authorize?client_id=\(formEncode(clientID.absoluteString))&request_uri=\(formEncode(requestURI))"

        do {
            let app = fixture.server.buildApplication(logger: Logger(label: "LocalhostOAuthBrowserHTTPTests.mfa"))
            try await app.test(.live) { client in
                var cookie: String?
                var csrf: String?
                try await client.execute(uri: authorize, method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                    let issuedCookie = try XCTUnwrap(response.headers[setCookieHeader])
                    cookie = self.cookieValue(issuedCookie)
                    csrf = try fixture.runtime.browserSessionService.verify(try XCTUnwrap(cookie)).csrfToken
                }

                // A direct phase-two submission has no password-admitted
                // OAuth phase and must fail before factor proof work.
                let directMFA = [
                    ("csrf", try XCTUnwrap(csrf)), ("handle", self.handle),
                    ("kind", "totp"), ("factorID", "oauth-totp-factor"), ("code", "000000")
                ].map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&")
                try await client.execute(
                    uri: "/oauth/authorize/mfa", method: .post,
                    headers: self.browserFormHeaders(cookie: try XCTUnwrap(cookie)),
                    body: ByteBuffer(string: directMFA)
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }

                var challengeCookie: String?
                var challengeCSRF: String?
                try await client.execute(
                    uri: authorize, method: .get
                ) { response in
                    let issuedCookie = try XCTUnwrap(response.headers[setCookieHeader])
                    challengeCookie = self.cookieValue(issuedCookie)
                    challengeCSRF = try fixture.runtime.browserSessionService.verify(try XCTUnwrap(challengeCookie)).csrfToken
                }
                let admittedLoginForm = [
                    ("csrf", try XCTUnwrap(challengeCSRF)), ("handle", self.handle), ("password", self.password)
                ].map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&")
                try await client.execute(
                    uri: "/oauth/authorize", method: .post,
                    headers: self.browserFormHeaders(cookie: try XCTUnwrap(challengeCookie)),
                    body: ByteBuffer(string: admittedLoginForm)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let html = String(decoding: Data(buffer: response.body), as: UTF8.self)
                    XCTAssertTrue(html.contains("/oauth/authorize/mfa"))
                    XCTAssertTrue(html.contains("name=\"kind\" value=\"totp\""))
                    XCTAssertFalse(html.contains("name=\"password\""))
                }

                // The phase is bound to the browser CSRF/session tuple, not
                // merely to the account and factor ID. A hostile-origin form
                // cannot spend the admitted phase with a substituted CSRF.
                let wrongCSRF = [
                    ("csrf", String(repeating: "z", count: 43)), ("handle", self.handle),
                    ("kind", "totp"), ("factorID", "oauth-totp-factor"), ("code", "000000")
                ].map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&")
                try await client.execute(
                    uri: "/oauth/authorize/mfa", method: .post,
                    headers: self.browserFormHeaders(cookie: try XCTUnwrap(challengeCookie)),
                    body: ByteBuffer(string: wrongCSRF)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                }

                let secret = try XCTUnwrap(fixture.totpSecret)
                let counter = UInt64(Date().timeIntervalSince1970 / 30)
                let code = try TOTPAuthenticator.code(secret: secret, counter: counter)
                let mfaForm = [
                    ("csrf", try XCTUnwrap(challengeCSRF)), ("handle", self.handle),
                    ("kind", "totp"), ("factorID", "oauth-totp-factor"), ("code", code)
                ].map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&")
                var consentCookie: String?
                try await client.execute(
                    uri: "/oauth/authorize/mfa", method: .post,
                    headers: self.browserFormHeaders(cookie: try XCTUnwrap(challengeCookie)),
                    body: ByteBuffer(string: mfaForm)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let html = String(decoding: Data(buffer: response.body), as: UTF8.self)
                    XCTAssertTrue(html.contains("Approve"))
                    consentCookie = self.cookieValue(try XCTUnwrap(response.headers[setCookieHeader]))
                }

                // The password-admitted phase and factor receipt are both
                // one-time. A replay cannot recreate consent.
                try await client.execute(
                    uri: "/oauth/authorize/mfa", method: .post,
                    headers: self.browserFormHeaders(cookie: try XCTUnwrap(challengeCookie)),
                    body: ByteBuffer(string: mfaForm)
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
                XCTAssertNotNil(consentCookie)
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testLocalOAuthPasskeyPageUsesServerChallengeAndNavigatorCredentials() async throws {
        let fixture = try await makeFixture(withPasskey: true)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let requestSession = try makeSession(
            proofID: "localhost-passkey-page",
            keyThumbprint: String(repeating: "k", count: 43)
        )
        let requestURI = try await fixture.runtime.tokenService.createPushedAuthorizationRequest(
            session: requestSession, state: "passkey-state", codeChallengeS256: String(repeating: "a", count: 43)
        )
        let authorize = "/oauth/authorize?client_id=\(formEncode(clientID.absoluteString))&request_uri=\(formEncode(requestURI))"
        do {
            let app = fixture.server.buildApplication(logger: Logger(label: "LocalhostOAuthBrowserHTTPTests.passkey"))
            try await app.test(.live) { client in
                var cookie: String?
                var csrf: String?
                try await client.execute(uri: authorize, method: .get) { response in
                    let value = try XCTUnwrap(response.headers[setCookieHeader])
                    cookie = self.cookieValue(value)
                    csrf = try fixture.runtime.browserSessionService.verify(try XCTUnwrap(cookie)).csrfToken
                }
                let form = [
                    ("csrf", try XCTUnwrap(csrf)), ("handle", self.handle), ("password", self.password)
                ].map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&")
                try await client.execute(
                    uri: "/oauth/authorize", method: .post,
                    headers: self.browserFormHeaders(cookie: try XCTUnwrap(cookie)),
                    body: ByteBuffer(string: form)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let html = String(decoding: Data(buffer: response.body), as: UTF8.self)
                    XCTAssertTrue(html.contains("navigator.credentials.get"))
                    XCTAssertTrue(html.contains("name=\"challenge\""))
                    XCTAssertTrue(html.contains("name=\"clientDataJSON\""))
                    XCTAssertTrue(html.contains("name=\"authenticatorData\""))
                    XCTAssertTrue(html.contains("name=\"credentialID\""))
                    XCTAssertTrue(html.contains("name=\"signature\""))
                }
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testLocalOAuthRecoveryOnlyFlowRendersCodeAndConsumesOnce() async throws {
        let fixture = try await makeFixture(withRecovery: true)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let requestSession = try makeSession(
            proofID: "localhost-recovery-flow",
            keyThumbprint: String(repeating: "r", count: 43)
        )
        let requestURI = try await fixture.runtime.tokenService.createPushedAuthorizationRequest(
            session: requestSession, state: "recovery-state", codeChallengeS256: String(repeating: "a", count: 43)
        )
        let authorize = "/oauth/authorize?client_id=\(formEncode(clientID.absoluteString))&request_uri=\(formEncode(requestURI))"
        do {
            let app = fixture.server.buildApplication(logger: Logger(label: "LocalhostOAuthBrowserHTTPTests.recovery"))
            try await app.test(.live) { client in
                var cookie: String?
                var csrf: String?
                try await client.execute(uri: authorize, method: .get) { response in
                    let value = try XCTUnwrap(response.headers[setCookieHeader])
                    cookie = self.cookieValue(value)
                    csrf = try fixture.runtime.browserSessionService.verify(try XCTUnwrap(cookie)).csrfToken
                }
                let login = [
                    ("csrf", try XCTUnwrap(csrf)), ("handle", self.handle), ("password", self.password)
                ].map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&")
                try await client.execute(
                    uri: "/oauth/authorize", method: .post,
                    headers: self.browserFormHeaders(cookie: try XCTUnwrap(cookie)),
                    body: ByteBuffer(string: login)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    let html = String(decoding: Data(buffer: response.body), as: UTF8.self)
                    XCTAssertTrue(html.contains("name=\"code\""))
                    XCTAssertTrue(html.contains("recovery"))
                }
                let mfa = [
                    ("csrf", try XCTUnwrap(csrf)), ("handle", self.handle),
                    ("kind", "recoveryCode"), ("factorID", "oauth-recovery-factor"),
                    ("code", try XCTUnwrap(fixture.recoveryCode))
                ].map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&")
                try await client.execute(
                    uri: "/oauth/authorize/mfa", method: .post,
                    headers: self.browserFormHeaders(cookie: try XCTUnwrap(cookie)),
                    body: ByteBuffer(string: mfa)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertTrue(String(decoding: Data(buffer: response.body), as: UTF8.self).contains("Approve"))
                }
                try await client.execute(
                    uri: "/oauth/authorize/mfa", method: .post,
                    headers: self.browserFormHeaders(cookie: try XCTUnwrap(cookie)),
                    body: ByteBuffer(string: mfa)
                ) { response in
                    XCTAssertEqual(response.status, .unauthorized)
                }
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testLocalBrowserFlowRejectsBadPasswordAndCSRFWithoutCode() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let session = try makeSession(proofID: "browser-negative-proof", keyThumbprint: String(repeating: "a", count: 43))
        let requestURI = try await fixture.runtime.tokenService.createPushedAuthorizationRequest(
            session: session,
            state: "negative-state",
            codeChallengeS256: String(repeating: "a", count: 43)
        )
        let query = "/oauth/authorize?client_id=\(formEncode(clientID.absoluteString))&request_uri=\(formEncode(requestURI))"

        do {
            let app = fixture.server.buildApplication(logger: Logger(label: "LocalhostOAuthBrowserHTTPTests.negative"))
            try await app.test(.live) { client in
                var cookie: String?
                try await client.execute(uri: query, method: .get) { response in
                    cookie = self.cookieValue(try XCTUnwrap(response.headers[setCookieHeader]))
                }
                let badLogin = "csrf=\(String(repeating: "a", count: 43))&handle=\(formEncode(handle))&password=wrong"
                try await client.execute(
                    uri: "/oauth/authorize",
                    method: .post,
                    headers: browserFormHeaders(cookie: try XCTUnwrap(cookie)),
                    body: ByteBuffer(string: badLogin)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                }
                let active = try await fixture.runtime.tokenService.activePushedAuthorizationRequest(requestURI)
                XCTAssertNotNil(active)
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testQualifiedScopeTraversesPARBrowserTokenAndRefreshHTTP() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let scope = "space:app.example.space?authority=\(did)&skey=whole-space&action=read"
        let scopedClientID = try XCTUnwrap(URL(string: "http://localhost?scope=\(formEncode(scope))&redirect_uri=\(formEncode(redirectURI.absoluteString))"))
        let verifier = "swan-localhost-qualified-http-verifier-000000000000000"
        let challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString()
        let key = P256.Signing.PrivateKey()
        let jwk = try makeJWK(key)
        let parForm = [
            ("client_id", scopedClientID.absoluteString), ("redirect_uri", redirectURI.absoluteString),
            ("response_type", "code"), ("scope", scope), ("state", "qualified-state"),
            ("code_challenge", challenge), ("code_challenge_method", "S256"),
        ].map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&")
        do {
            let app = fixture.server.buildApplication(logger: Logger(label: "LocalhostOAuthBrowserHTTPTests.qualifiedHTTP"))
            try await app.test(.live) { client in
                var parNonce: String?
                try await client.execute(uri: "/oauth/par", method: .post, headers: tokenHeaders(), body: ByteBuffer(string: parForm)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    parNonce = response.headers[dpopNonceHeader]
                }
                let parProof = try makeDPoPProof(key: key, jwk: jwk, jti: "qualified-par", nonce: try XCTUnwrap(parNonce), target: try OAuthDPoPProofValidator.normalizedTarget(issuer.appending(path: "oauth/par")))
                var requestURI: String?
                try await client.execute(uri: "/oauth/par", method: .post, headers: tokenHeaders(dpop: parProof), body: ByteBuffer(string: parForm)) { response in
                    XCTAssertEqual(response.status, .created)
                    requestURI = (try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: response.body)) as? [String: Any]))["request_uri"] as? String
                }
                let authorize = "/oauth/authorize?client_id=\(formEncode(scopedClientID.absoluteString))&request_uri=\(formEncode(try XCTUnwrap(requestURI)))"
                var loginCookie: String?
                var loginCSRF: String?
                try await client.execute(uri: authorize, method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                    loginCookie = self.cookieValue(try XCTUnwrap(response.headers[setCookieHeader]))
                    loginCSRF = try fixture.runtime.browserSessionService.verify(try XCTUnwrap(loginCookie)).csrfToken
                }
                let login = [("csrf", try XCTUnwrap(loginCSRF)), ("handle", handle), ("password", password)]
                    .map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&")
                var consentCookie: String?
                var consentCSRF: String?
                try await client.execute(uri: "/oauth/authorize", method: .post, headers: browserFormHeaders(cookie: try XCTUnwrap(loginCookie)), body: ByteBuffer(string: login)) { response in
                    XCTAssertEqual(response.status, .ok)
                    let consentHTML = String(
                        decoding: Data(buffer: response.body),
                        as: UTF8.self
                    )
                    XCTAssertTrue(
                        consentHTML.contains(
                            ">\(scope.replacingOccurrences(of: "&", with: "&amp;"))</code>"
                        )
                    )
                    consentCookie = self.cookieValue(try XCTUnwrap(response.headers[setCookieHeader]))
                    consentCSRF = try fixture.runtime.browserSessionService.verify(try XCTUnwrap(consentCookie)).csrfToken
                }
                var code: String?
                try await client.execute(uri: "/oauth/authorize/consent", method: .post, headers: browserFormHeaders(cookie: try XCTUnwrap(consentCookie)), body: ByteBuffer(string: "csrf=\(formEncode(try XCTUnwrap(consentCSRF)))&decision=approve")) { response in
                    XCTAssertEqual(response.status, .found)
                    let items = try XCTUnwrap(URLComponents(string: try XCTUnwrap(response.headers[.location]))?.queryItems)
                    code = items.first(where: { $0.name == "code" })?.value
                }
                let codeForm = [
                    ("grant_type", "authorization_code"), ("client_id", scopedClientID.absoluteString),
                    ("redirect_uri", redirectURI.absoluteString), ("code", try XCTUnwrap(code)), ("code_verifier", verifier),
                ].map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&")
                var tokenNonce: String?
                try await client.execute(uri: "/oauth/token", method: .post, headers: tokenHeaders(), body: ByteBuffer(string: codeForm)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    tokenNonce = response.headers[dpopNonceHeader]
                }
                let tokenTarget = try OAuthDPoPProofValidator.normalizedTarget(issuer.appending(path: "oauth/token"))
                let codeProof = try makeDPoPProof(key: key, jwk: jwk, jti: "qualified-code", nonce: try XCTUnwrap(tokenNonce), target: tokenTarget)
                var refresh: String?
                try await client.execute(uri: "/oauth/token", method: .post, headers: tokenHeaders(dpop: codeProof), body: ByteBuffer(string: codeForm)) { response in
                    XCTAssertEqual(response.status, .ok)
                    let tokens = try self.tokenResponse(from: response.body)
                    XCTAssertEqual(tokens["scope"], scope)
                    refresh = tokens["refresh_token"]
                }
                let refreshForm = [("grant_type", "refresh_token"), ("client_id", scopedClientID.absoluteString), ("refresh_token", try XCTUnwrap(refresh))]
                    .map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&")
                let refreshProof = try makeDPoPProof(key: key, jwk: jwk, jti: "qualified-refresh", nonce: try XCTUnwrap(tokenNonce), target: tokenTarget)
                var rotatedRefresh: String?
                try await client.execute(uri: "/oauth/token", method: .post, headers: tokenHeaders(dpop: refreshProof), body: ByteBuffer(string: refreshForm)) { response in
                    XCTAssertEqual(response.status, .ok)
                    let tokens = try self.tokenResponse(from: response.body)
                    XCTAssertEqual(tokens["scope"], scope)
                    rotatedRefresh = tokens["refresh_token"]
                }
                let widening = [
                    ("grant_type", "refresh_token"), ("client_id", scopedClientID.absoluteString),
                    ("refresh_token", try XCTUnwrap(rotatedRefresh)), ("scope", "atproto"),
                ].map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&")
                let wideningProof = try makeDPoPProof(key: key, jwk: jwk, jti: "qualified-widen", nonce: try XCTUnwrap(tokenNonce), target: tokenTarget)
                try await client.execute(uri: "/oauth/token", method: .post, headers: tokenHeaders(dpop: wideningProof), body: ByteBuffer(string: widening)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(try self.errorCode(from: response.body), "invalid_grant")
                }
                XCTAssertNotNil(rotatedRefresh)
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testLocalRevocationConsumesAValidDPoPProofAndRevokesTheWholeFamily() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let signingKey = P256.Signing.PrivateKey()
        let jwk = try makeJWK(signingKey)
        let session = try makeSession(proofID: "browser-revoke-issue", keyThumbprint: jwk.thumbprint())
        let tokens = try await fixture.runtime.tokenService.issue(subject: did, session: session)
        let form = [
            ("token", tokens.accessToken),
            ("client_id", clientID.absoluteString),
            ("token_type_hint", "access_token"),
        ].map { "\(formEncode($0.0))=\(formEncode($0.1))" }.joined(separator: "&")
        do {
            let app = fixture.server.buildApplication(logger: Logger(label: "LocalhostOAuthBrowserHTTPTests.revoke"))
            try await app.test(.router) { client in
                var nonce: String?
                try await client.execute(
                    uri: "/oauth/revoke",
                    method: .post,
                    headers: tokenHeaders(),
                    body: ByteBuffer(string: form)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    nonce = response.headers[dpopNonceHeader]
                    XCTAssertEqual(try self.errorCode(from: response.body), "use_dpop_nonce")
                }
                let proof = try makeDPoPProof(
                    key: signingKey,
                    jwk: jwk,
                    jti: "browser-revoke-proof",
                    nonce: try XCTUnwrap(nonce),
                    target: try OAuthDPoPProofValidator.normalizedTarget(issuer.appending(path: "oauth/revoke"))
                )
                try await client.execute(
                    uri: "/oauth/revoke",
                    method: .post,
                    headers: tokenHeaders(dpop: proof),
                    body: ByteBuffer(string: form)
                ) { response in
                    XCTAssertEqual(response.status, .ok)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                }
            }
            await XCTAssertThrowsAsync(
                try await fixture.runtime.tokenService.validateAccess(
                    tokens.accessToken,
                    proof: session.dpopProof
                )
            )
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testQualifiedScopeSurvivesCodeAndRefreshAndCannotBeWidened() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let scope = "space:app.example.space?authority=\(did)&skey=whole-space&action=read"
        let qualifiedClientID = try XCTUnwrap(URL(string: "http://localhost?scope=\(formEncode(scope))&redirect_uri=\(formEncode(redirectURI.absoluteString))"))
        let key = P256.Signing.PrivateKey()
        let jwk = try makeJWK(key)
        let session = try makeSession(
            proofID: "qualified-code", keyThumbprint: jwk.thumbprint(), clientID: qualifiedClientID, scopes: [scope]
        )
        let verifier = "swan-localhost-qualified-scope-verifier-0000000000000"
        let code = try await fixture.runtime.tokenService.issueAuthorizationCode(
            subject: did,
            session: session,
            codeChallengeS256: Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString()
        )
        let metadata = try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: qualifiedClientID)
        let issued = try await fixture.runtime.tokenService.redeemAuthorizationCodeForClient(
            code, verifier: verifier, redirectURI: redirectURI, authorizationServerIssuer: issuer.absoluteString,
            client: OAuthResolvedClientMetadata(metadata: metadata, keySet: nil), dpopProof: session.dpopProof, clientAssertion: nil
        )
        XCTAssertEqual(issued.scopes, [scope])
        let refresh = try XCTUnwrap(issued.refreshToken)
        do {
            _ = try await fixture.runtime.tokenService.redeemLocalhostPublicRefresh(
                refresh, clientID: qualifiedClientID, dpopProof: session.dpopProof, requestedScopes: ["atproto"]
            )
            XCTFail("refresh scope widening was accepted")
        } catch {}
        let refreshed = try await fixture.runtime.tokenService.redeemLocalhostPublicRefresh(
            refresh, clientID: qualifiedClientID, dpopProof: session.dpopProof, requestedScopes: [scope]
        )
        let grant = try await fixture.runtime.tokenService.validateAccess(
            refreshed.accessToken,
            proof: session.dpopProof
        )
        XCTAssertEqual(grant.scopes, [scope])
        try await fixture.control.close()
    }

    private func makeFixture(
        loginClientIdentityPolicy: SwanLoginClientIdentityPolicy? = nil,
        loginAdmissionStore: (any AccountLoginAdmissionStore)? = nil,
        withTOTP: Bool = false,
        withPasskey: Bool = false,
        withRecovery: Bool = false
    ) async throws -> (
        server: SwanHTTPServer,
        runtime: SwanOAuthRuntime,
        control: SQLiteControlDatabase,
        root: URL,
        totpSecret: Data?,
        recoveryCode: String?
    ) {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "LocalhostOAuthBrowserHTTPTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let hasher = try LibsodiumArgon2idHasher(policy: .interactive)
            let admissionStore: any AccountLoginAdmissionStore
            if let loginAdmissionStore {
                admissionStore = loginAdmissionStore
            } else {
                admissionStore = control
            }
            let factorTokenService = FactorTokenService(store: control)
            let directory = DurableAccountDirectory(
                store: control,
                passwordHasher: hasher,
                verificationExecutor: try Argon2idVerificationExecutor(hasher: hasher),
                loginAdmissionService: AccountLoginAdmissionService(
                    store: admissionStore,
                    key: try AccountLoginAdmissionKey(
                        Data(repeating: 0xD5, count: 32)
                    )
                ),
                loginFactorTokenVerifier: factorTokenService,
                authenticationFactors: control
            )
            _ = try await directory.registerProvisionedAccount(
                did: did,
                canonicalHandle: handle,
                password: password,
                signingReference: try AccountKeyReference(accountDID: did, purpose: .signing, generation: 1),
                rotationReference: try AccountKeyReference(accountDID: did, purpose: .rotation, generation: 1)
            )
            let runtime = try SwanOAuthRuntime(controlStore: control, serverKey: Data(repeating: 0xD5, count: 32))
            let profile = try ProtocolProfile.load(
                from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
            )
            var totpSecret: Data?
            var recoveryCode: String?
            var mfaService: (any SwanOAuthMFAService)?
            let factorID: String
            if withTOTP {
                let secret = Data("12345678901234567890".utf8)
                factorID = "oauth-totp-factor"
                let factor = try AuthenticationFactorMetadata(
                    id: factorID,
                    accountDID: did,
                    kind: .totp,
                    label: "Authenticator",
                    lookupDigest: Data(repeating: 0x5A, count: 32),
                    createdAt: Date()
                )
                try await control.saveFactor(factor, now: Date())
                try await control.saveTOTPEnvelope(
                    try TOTPEnvelopeCrypto.seal(
                        secret: secret,
                        factorID: factorID,
                        keyReference: "account-kek:primary",
                        key: Data(repeating: 0x4B, count: 32)
                    ),
                    now: Date()
                )
                totpSecret = secret
            } else if withPasskey {
                factorID = "oauth-passkey-factor"
                try await control.saveFactor(
                    try AuthenticationFactorMetadata(
                        id: factorID,
                        accountDID: did,
                        kind: .passkey,
                        label: "Passkey",
                        lookupDigest: Data(repeating: 0x5B, count: 32),
                        createdAt: Date()
                    ),
                    now: Date()
                )
            } else if withRecovery {
                factorID = "oauth-recovery-factor"
                try await control.saveFactor(
                    try AuthenticationFactorMetadata(
                        id: factorID,
                        accountDID: did,
                        kind: .recoveryCode,
                        label: "Recovery",
                        lookupDigest: Data(repeating: 0x5C, count: 32),
                        createdAt: Date()
                    ),
                    now: Date()
                )
                let code = "RECOVERY-CODE-LOCAL-ONLY"
                try await control.replaceRecoveryCodeDigests(
                    accountDID: did,
                    digests: [try RecoveryCodeDigest(
                        accountDID: did,
                        digest: RecoveryCodeService.digest(code),
                        issuedAt: Date()
                    )],
                    now: Date()
                )
                recoveryCode = code
            } else {
                factorID = ""
            }
            if withTOTP || withPasskey || withRecovery {
                let accountMFA = try SwanAccountPortalMFARuntime(
                    factors: control,
                    totpSecrets: control,
                    replayStore: control,
                    recoveryStore: control,
                    webAuthnCredentials: control,
                    webAuthnChallenges: control,
                    webAuthnEnrollmentStore: control,
                    factorTokens: factorTokenService,
                    accountKEK: Data(repeating: 0x4B, count: 32),
                    accountKEKID: "primary",
                    relyingPartyID: "swan.example",
                    origin: issuer.absoluteString
                )
                mfaService = SwanOAuthMFAServiceAdapter(factors: control, oauthMFA: accountMFA)
            }
            let oauthConfiguration = try SwanLocalhostOAuthConfiguration(
                issuer: issuer,
                accounts: directory,
                mfaService: mfaService
            )
            let server = SwanHTTPServer(
                profile: profile,
                configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: issuer),
                oauthRuntime: runtime,
                localhostOAuthConfiguration: oauthConfiguration,
                loginClientIdentityPolicy:
                    loginClientIdentityPolicy ?? SwanLoginClientIdentityPolicy.direct
            )
            return (
                server,
                runtime,
                control,
                root,
                totpSecret,
                recoveryCode
            )
        } catch {
            try? await control.close()
            throw error
        }
    }

    private func makeSession(
        proofID: String,
        keyThumbprint: String,
        clientID: URL? = nil,
        scopes: Set<String> = ["atproto"]
    ) throws -> OAuthValidatedSession {
        let metadata = try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: clientID ?? self.clientID)
        return try OAuthValidatedSession(
            issuer: issuer.absoluteString,
            client: OAuthResolvedClientMetadata(metadata: metadata, keySet: nil),
            redirectURI: redirectURI,
            scopes: scopes,
            dpopProof: OAuthValidatedDPoPProof(
                keyThumbprint: keyThumbprint,
                jwtID: proofID,
                issuedAt: Date()
            )
        )
    }

    private func browserFormHeaders(cookie: String) -> HTTPFields {
        var headers: HTTPFields = [.contentType: "application/x-www-form-urlencoded"]
        headers[.cookie] = "__Host-swan-oauth=\(cookie)"
        return headers
    }

    private func assertStrictBrowserSecurityHeaders(
        _ headers: HTTPFields,
        contentType: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertEqual(headers[.contentType], contentType, file: file, line: line)
        XCTAssertEqual(headers[.cacheControl], "no-store", file: file, line: line)
        XCTAssertEqual(
            headers[contentSecurityPolicyHeader],
            "default-src 'none'; style-src \(SwanBrowserPages.browserStyleCSPSource); "
                + "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            file: file,
            line: line
        )
        // The stylesheet source must be a hash, never a relaxation.
        XCTAssertTrue(
            SwanBrowserPages.browserStyleCSPSource.hasPrefix("'sha256-"),
            file: file,
            line: line
        )
        XCTAssertEqual(headers[xFrameOptionsHeader], "DENY", file: file, line: line)
        XCTAssertEqual(headers[referrerPolicyHeader], "no-referrer", file: file, line: line)
        XCTAssertEqual(headers[xContentTypeOptionsHeader], "nosniff", file: file, line: line)
    }

    private func tokenHeaders(dpop: String? = nil) -> HTTPFields {
        var headers: HTTPFields = [.contentType: "application/x-www-form-urlencoded"]
        if let dpop { headers[dpopHeader] = dpop }
        return headers
    }

    private func makeJWK(_ key: P256.Signing.PrivateKey) throws -> OAuthJSONWebKey {
        let representation = key.publicKey.x963Representation
        return try OAuthJSONWebKey(
            x: Data(representation[1 ..< 33]).base64URLEncodedString(),
            y: Data(representation[33 ..< 65]).base64URLEncodedString()
        )
    }

    private func makeDPoPProof(
        key: P256.Signing.PrivateKey,
        jwk: OAuthJSONWebKey,
        jti: String,
        nonce: String,
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
        let header = try encoder.encode(Header(jwk: jwk)).base64URLEncodedString()
        let claims = try encoder.encode(Claims(
            jti: jti,
            iat: Int64(Date().timeIntervalSince1970),
            htu: target,
            nonce: nonce
        )).base64URLEncodedString()
        let input = "\(header).\(claims)"
        return "\(input).\(try P256WireSignature.sign(Data(input.utf8), using: key).base64URLEncodedString())"
    }

    private func tokenResponse(from body: ByteBuffer) throws -> [String: String] {
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: body)) as? [String: Any])
        return object.compactMapValues { $0 as? String }
    }

    private func errorCode(from body: ByteBuffer) throws -> String {
        try XCTUnwrap(tokenResponse(from: body)["error"])
    }

    private func cookieValue(_ setCookie: String) -> String? {
        setCookie.split(separator: ";", maxSplits: 1).first
            .flatMap { $0.split(separator: "=", maxSplits: 1).dropFirst().first }
            .map(String.init)
    }

    private func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}

private actor CountingLoginAdmissionStore: AccountLoginAdmissionStore {
    private var invocations = 0

    func consumeLoginRateLimit(
        _: AccountLoginRateLimitRequest,
        now _: Date
    ) async throws -> AccountLoginRateLimitDecision {
        invocations += 1
        return .allowed
    }

    func invocationCount() -> Int {
        invocations
    }
}

private let setCookieHeader = HTTPField.Name("Set-Cookie")!
private let dpopHeader = HTTPField.Name("DPoP")!
private let dpopNonceHeader = HTTPField.Name("DPoP-Nonce")!
private let contentSecurityPolicyHeader = HTTPField.Name("Content-Security-Policy")!
private let xFrameOptionsHeader = HTTPField.Name("X-Frame-Options")!
private let referrerPolicyHeader = HTTPField.Name("Referrer-Policy")!
private let xContentTypeOptionsHeader = HTTPField.Name("X-Content-Type-Options")!

private func formEncode(_ value: String) -> String {
    value.utf8.map { byte in
        switch byte {
        case 65 ... 90, 97 ... 122, 48 ... 57, 45, 46, 95, 126:
            String(UnicodeScalar(byte))
        case 32:
            "+"
        default:
            String(format: "%%%02X", byte)
        }
    }.joined()
}

private func XCTAssertThrowsAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("Expected expression to throw", file: file, line: line)
    } catch {
        // Expected.
    }
}
