import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import XCTest
import SwanAccounts
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite

final class LocalhostOAuthBrowserHTTPTests: XCTestCase, @unchecked Sendable {
    private let issuer = URL(string: "https://swan.example")!
    private let clientID = URL(string: "http://localhost?scope=atproto&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback")!
    private let redirectURI = URL(string: "http://127.0.0.1/callback")!
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let handle = "alice.swan.test"
    private let password = "correct horse battery staple"

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
            try await app.test(.router) { client in
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
                    let cookie = try XCTUnwrap(response.headers[setCookieHeader])
                    consentCookie = self.cookieValue(cookie)
                    let session = try fixture.runtime.browserSessionService.verify(try XCTUnwrap(consentCookie))
                    XCTAssertEqual(session.subject, self.did)
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
            try await app.test(.router) { client in
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
                try await fixture.runtime.tokenService.validateAccess(tokens.accessToken, proof: session.dpopProof)
            )
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    private func makeFixture() async throws -> (server: SwanHTTPServer, runtime: SwanOAuthRuntime, control: SQLiteControlDatabase, root: URL) {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "LocalhostOAuthBrowserHTTPTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let hasher = try LibsodiumArgon2idHasher(policy: .interactive)
            let directory = DurableAccountDirectory(
                store: control,
                passwordHasher: hasher,
                verificationExecutor: try Argon2idVerificationExecutor(hasher: hasher)
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
            let oauthConfiguration = try SwanLocalhostOAuthConfiguration(issuer: issuer, accounts: directory)
            let server = SwanHTTPServer(
                profile: profile,
                configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: issuer),
                oauthRuntime: runtime,
                localhostOAuthConfiguration: oauthConfiguration
            )
            return (
                server,
                runtime,
                control,
                root
            )
        } catch {
            try? await control.close()
            throw error
        }
    }

    private func makeSession(proofID: String, keyThumbprint: String) throws -> OAuthValidatedSession {
        let metadata = try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: clientID)
        return try OAuthValidatedSession(
            issuer: issuer.absoluteString,
            client: OAuthResolvedClientMetadata(metadata: metadata, keySet: nil),
            redirectURI: redirectURI,
            scopes: ["atproto"],
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

private let setCookieHeader = HTTPField.Name("Set-Cookie")!
private let dpopHeader = HTTPField.Name("DPoP")!
private let dpopNonceHeader = HTTPField.Name("DPoP-Nonce")!

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
