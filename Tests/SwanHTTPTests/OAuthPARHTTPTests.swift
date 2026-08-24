import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import NIOCore
import PetrelCrypto
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite
import SwanStorage
import XCTest

final class OAuthPARHTTPTests: XCTestCase, @unchecked Sendable {
    private let issuer = URL(string: "https://swan.example")!
    private let clientID = URL(string: "http://localhost?scope=atproto")!
    private let redirectURI = URL(string: "http://127.0.0.1/")!
    private let qualifiedScope = "space:app.example.space?authority=did:plc:abcdefghijklmnopqrstuvwx&skey=whole-space&action=read"

    func testLocalhostPARIsClosedByDefaultAndRequiresHTTPSIssuer() async throws {
        XCTAssertThrowsError(try SwanLocalhostPARConfiguration(issuer: URL(string: "http://swan.example")!))
        let fixture = try await makeFixture(enablePAR: false)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = fixture.server.buildApplication(logger: Logger(label: "OAuthPARHTTPTests.closed"))
            try await app.test(.router) { client in
                try await client.execute(uri: "/oauth/par", method: .post) { response in
                    XCTAssertEqual(response.status, .notFound)
                }
                for path in [
                    "/.well-known/oauth-protected-resource",
                    "/.well-known/oauth-authorization-server",
                    "/oauth/authorize",
                ] {
                    try await client.execute(uri: path, method: .get) { response in
                        XCTAssertEqual(response.status, .serviceUnavailable, path)
                    }
                }
                for path in ["/oauth/token", "/oauth/revoke"] {
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

    func testEnabledLocalhostPARChallengesThenPersistsOneDPoPBoundRequest() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let form = validForm(state: "first-state")
        let signingKey = P256.Signing.PrivateKey()
        let jwk = try makeJWK(signingKey)
        do {
            let app = fixture.server.buildApplication(logger: Logger(label: "OAuthPARHTTPTests.par"))
            try await app.test(.router) { client in
                var nonce: String?
                try await client.execute(
                    uri: "/oauth/par",
                    method: .post,
                    headers: formHeaders(),
                    body: ByteBuffer(string: form)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    XCTAssertEqual(response.headers[.contentType], "application/json")
                    XCTAssertEqual(response.headers[.wwwAuthenticate], "DPoP error=\"use_dpop_nonce\"")
                    nonce = response.headers[dpopNonceHeader]
                    XCTAssertEqual(try self.errorCode(from: response.body), "use_dpop_nonce")
                }
                let challenge = try XCTUnwrap(nonce)
                let wrongTargetProof = try makeDPoPProof(
                    key: signingKey,
                    jwk: jwk,
                    jti: "dpop-http-wrong-target",
                    nonce: challenge,
                    target: "https://swan.example/not-oauth-par"
                )
                try await client.execute(
                    uri: "/oauth/par",
                    method: .post,
                    headers: formHeaders(dpop: wrongTargetProof),
                    body: ByteBuffer(string: form)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    XCTAssertNotNil(response.headers[dpopNonceHeader])
                    XCTAssertEqual(try self.errorCode(from: response.body), "use_dpop_nonce")
                }
                let proof = try makeDPoPProof(
                    key: signingKey,
                    jwk: jwk,
                    jti: "dpop-http-success",
                    nonce: challenge,
                    target: try OAuthDPoPProofValidator.normalizedTarget(issuer.appending(path: "oauth/par"))
                )
                var requestURI: String?
                try await client.execute(
                    uri: "/oauth/par",
                    method: .post,
                    headers: formHeaders(dpop: proof),
                    body: ByteBuffer(string: form)
                ) { response in
                    XCTAssertEqual(response.status, .created)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    XCTAssertEqual(response.headers[.contentType], "application/json")
                    let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: response.body)) as? [String: Any])
                    let value = try XCTUnwrap(object["request_uri"] as? String)
                    XCTAssertTrue(value.hasPrefix("urn:ietf:params:oauth:request_uri:"))
                    XCTAssertEqual(object["expires_in"] as? Int, 90)
                    requestURI = value
                }

                // Reusing an otherwise valid proof never creates a second PAR
                // and receives the same generic nonce challenge as every
                // other proof failure.
                try await client.execute(
                    uri: "/oauth/par",
                    method: .post,
                    headers: formHeaders(dpop: proof),
                    body: ByteBuffer(string: form)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    XCTAssertNotNil(response.headers[dpopNonceHeader])
                    XCTAssertEqual(try self.errorCode(from: response.body), "use_dpop_nonce")
                }

                // The stored request is bound to the DPoP key, issuer, client,
                // redirect URI, and scope. Consuming it through the durable API
                // demonstrates that the HTTP endpoint did not merely render an
                // opaque request URI.
                let nonceForConsumption = fixture.runtime.dpopNonceService.issue()
                let consumptionProof = try makeDPoPProof(
                    key: signingKey,
                    jwk: jwk,
                    jti: "dpop-http-consume",
                    nonce: nonceForConsumption,
                    target: try OAuthDPoPProofValidator.normalizedTarget(issuer.appending(path: "oauth/par"))
                )
                let validator = try OAuthDPoPProofValidator(runtime: fixture.runtime)
                let validatedProof = try await validator.validate(
                    consumptionProof,
                    request: OAuthDPoPRequest(
                        method: "POST",
                        target: issuer.appending(path: "oauth/par"),
                        serverNonce: nonceForConsumption
                    )
                )
                let metadata = try OAuthClientMetadata.localhostDevelopmentMetadata(clientID: clientID)
                let session = try OAuthValidatedSession(
                    issuer: issuer.absoluteString,
                    client: OAuthResolvedClientMetadata(metadata: metadata, keySet: nil),
                    redirectURI: redirectURI,
                    scopes: ["atproto"],
                    dpopProof: validatedProof
                )
                let persisted = try await fixture.runtime.tokenService.consumePushedAuthorizationRequest(
                    try XCTUnwrap(requestURI),
                    session: session
                )
                XCTAssertEqual(persisted.state, "first-state")
                XCTAssertEqual(persisted.codeChallengeMethod, .s256)
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testEnabledLocalhostPARAdmitsLoginHintAndInteractivePromptHints() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        // The atproto-oauth Rust crate sends the typed handle as `login_hint`
        // on every sign-in; refusing the hint refuses the client. The server
        // ignores both hints (it always presents the login form), so parsing
        // must reach the nonce challenge and then persist the request.
        let form = validForm(state: "hinted")
            + "&login_hint=\(formEncode("someone.example.com"))&prompt=login"
        let key = P256.Signing.PrivateKey()
        let jwk = try makeJWK(key)
        do {
            let app = fixture.server.buildApplication(logger: Logger(label: "OAuthPARHTTPTests.hints"))
            try await app.test(.router) { client in
                var nonce: String?
                try await client.execute(
                    uri: "/oauth/par",
                    method: .post,
                    headers: formHeaders(),
                    body: ByteBuffer(string: form)
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(
                        try self.errorCode(from: response.body),
                        "use_dpop_nonce",
                        "a hinted form must parse and be met with the nonce challenge, not invalid_request"
                    )
                    nonce = response.headers[dpopNonceHeader]
                }
                let proof = try makeDPoPProof(
                    key: key,
                    jwk: jwk,
                    jti: "dpop-hinted-success",
                    nonce: try XCTUnwrap(nonce),
                    target: try OAuthDPoPProofValidator.normalizedTarget(issuer.appending(path: "oauth/par"))
                )
                try await client.execute(
                    uri: "/oauth/par",
                    method: .post,
                    headers: formHeaders(dpop: proof),
                    body: ByteBuffer(string: form)
                ) { response in
                    XCTAssertEqual(response.status, .created)
                    let object = try XCTUnwrap(
                        JSONSerialization.jsonObject(with: Data(buffer: response.body)) as? [String: Any])
                    let value = try XCTUnwrap(object["request_uri"] as? String)
                    XCTAssertTrue(value.hasPrefix("urn:ietf:params:oauth:request_uri:"))
                }
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testLocalhostPARPreservesRegisteredQualifiedWholeSpaceScope() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let clientID = try XCTUnwrap(URL(string: "http://localhost?scope=\(formEncode(qualifiedScope))"))
        let form = validForm(state: "qualified", clientID: clientID, scope: qualifiedScope)
        let key = P256.Signing.PrivateKey()
        let jwk = try makeJWK(key)
        do {
            let app = fixture.server.buildApplication(logger: Logger(label: "OAuthPARHTTPTests.qualified"))
            try await app.test(.router) { client in
                var nonce: String?
                try await client.execute(uri: "/oauth/par", method: .post, headers: formHeaders(), body: ByteBuffer(string: form)) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    nonce = response.headers[dpopNonceHeader]
                }
                let proof = try makeDPoPProof(
                    key: key, jwk: jwk, jti: "qualified-scope", nonce: try XCTUnwrap(nonce),
                    target: try OAuthDPoPProofValidator.normalizedTarget(issuer.appending(path: "oauth/par"))
                )
                var requestURI: String?
                try await client.execute(uri: "/oauth/par", method: .post, headers: formHeaders(dpop: proof), body: ByteBuffer(string: form)) { response in
                    XCTAssertEqual(response.status, .created)
                    requestURI = (try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: response.body)) as? [String: Any]))["request_uri"] as? String
                }
                let active = try await fixture.runtime.tokenService.activePushedAuthorizationRequest(try XCTUnwrap(requestURI))
                XCTAssertEqual(active?.binding.scopes, [qualifiedScope])
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    /// Re-aimed for §9-D21, keeping the property the name states.
    ///
    /// The original list mixed two kinds of bad request and asserted a single
    /// outcome for both: `invalid_request`, pre-DPoP, no nonce. Two of its
    /// vectors — a bare `space:<type>` and a universal `space:*?authority=*` —
    /// were refused there only because `isIssuableQualified` gated issuance at
    /// registration. D21 deletes that gate, so they are no longer refused
    /// *early*. **They are still refused**; measured, every vector below is.
    ///
    /// What the measurement showed, and why the new shape is a STRONGER
    /// anti-oracle assertion than the old one:
    ///
    ///  * **Structurally** malformed forms (unknown parameter, duplicated
    ///    parameter, PKCE `plain`, mismatched redirect) are still refused
    ///    **before** DPoP, uniformly `invalid_request`, with **no** nonce. They
    ///    leak nothing about scopes because scopes are never reached.
    ///  * Every **scope-semantic** form is now indistinguishable from a
    ///    perfectly valid request at that first stage: it receives the *same*
    ///    nonce challenge. Early rejection of those forms was itself the oracle
    ///    — it told an unauthenticated caller which scope shapes the server
    ///    dislikes, before the caller had proved possession of any key. Deferring
    ///    the decision behind DPoP removes that.
    ///  * Only **after** the nonce is each one refused, and none reaches a
    ///    `request_uri`.
    func testEnabledLocalhostPARRefusesEveryBroadFormWithoutOpeningAnOAuthErrorOracle() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let app = fixture.server.buildApplication(logger: Logger(label: "OAuthPARHTTPTests.strict"))
            try await app.test(.router) { client in
                // Refused BEFORE DPoP: the request is malformed as a request, so
                // no scope is ever consulted.
                let structurallyMalformed = [
                    validForm(state: "unknown") + "&unexpected=value",
                    validForm(state: "duplicate") + "&scope=atproto",
                    // `prompt=none` demands a silent answer; this server always
                    // presents the login form, so accepting it would leave the
                    // client waiting on a redirect that needs a human.
                    validForm(state: "prompt-none") + "&prompt=none",
                    validForm(state: "prompt-unknown") + "&prompt=create",
                    validForm(state: "hint-empty") + "&login_hint=",
                    validForm(state: "plain").replacingOccurrences(
                        of: "code_challenge_method=S256", with: "code_challenge_method=plain"
                    ),
                    validForm(state: "redirect").replacingOccurrences(
                        of: formEncode(redirectURI.absoluteString),
                        with: formEncode("https://client.example/callback")
                    ),
                ]
                for form in structurallyMalformed {
                    try await client.execute(
                        uri: "/oauth/par",
                        method: .post,
                        headers: formHeaders(),
                        body: ByteBuffer(string: form)
                    ) { response in
                        XCTAssertEqual(response.status, .badRequest)
                        XCTAssertEqual(response.headers[.cacheControl], "no-store")
                        XCTAssertNil(
                            response.headers[dpopNonceHeader],
                            "a structurally malformed request must not be handed a nonce"
                        )
                        XCTAssertEqual(try self.errorCode(from: response.body), "invalid_request")
                    }
                }

                // Scope-semantic forms. Each is refused, but only after DPoP —
                // and the expected post-nonce code is recorded per vector so a
                // change of layer or reason is visible rather than absorbed.
                let scopeSemantic: [(state: String, form: String, code: String)] = [
                    // An unknown scope NAME (§9-D5: rejected, never silently dropped).
                    ("scope", validForm(state: "scope").replacingOccurrences(
                        of: "scope=atproto", with: "scope=atproto%20profile"
                    ), "invalid_scope"),
                    // §7.3 D8 — a percent-decoded key collision stays rejected.
                    ("duplicate-dimension", validForm(state: "duplicate-dimension").replacingOccurrences(
                        of: "scope=atproto",
                        with: "scope=space%3Aapp.example.space%3Fauthority%3Ddid%3Aplc%3Aabcdefghijklmnopqrstuvwx%26%2561uthority%3Ddid%3Aplc%3Aabcdefghijklmnopqrstuvwx%26skey%3Dwhole-space%26action%3Dread"
                    ), "invalid_scope"),
                    // The two RETIRED-GATE vectors. Both parse now (D21), and both
                    // are refused for the reason that actually applies: the
                    // localhost client registered `atproto` and nothing else, so
                    // requested-⊄-declared fails. Registration declares, PAR
                    // enforces the subset — which is D21's layering, working.
                    ("bare", validForm(state: "bare").replacingOccurrences(
                        of: "scope=atproto", with: "scope=space%3Aapp.example.space"
                    ), "invalid_request"),
                    ("wildcard", validForm(state: "wildcard").replacingOccurrences(
                        of: "scope=atproto",
                        with: "scope=space%3A%2A%3Fauthority%3D%2A%26skey%3D%2A%26action%3Dread"
                    ), "invalid_request"),
                    // A well-formed scope the client never registered — the same
                    // subset refusal, stated explicitly so the two above are not
                    // the only evidence for it.
                    ("unregistered", validForm(state: "unregistered").replacingOccurrences(
                        of: "scope=atproto",
                        with: "scope=space%3Aapp.example.space%3Fauthority%3Ddid%3Aplc%3Aabcdefghijklmnopqrstuvwx%26skey%3Dwhole-space%26action%3Dread"
                    ), "invalid_request"),
                ]
                let key = P256.Signing.PrivateKey()
                let jwk = try makeJWK(key)
                for vector in scopeSemantic {
                    // Stage 1 — indistinguishable from a valid request.
                    var challenge: String?
                    try await client.execute(
                        uri: "/oauth/par",
                        method: .post,
                        headers: formHeaders(),
                        body: ByteBuffer(string: vector.form)
                    ) { response in
                        XCTAssertEqual(response.status, .badRequest, vector.state)
                        XCTAssertEqual(response.headers[.cacheControl], "no-store", vector.state)
                        XCTAssertEqual(
                            try self.errorCode(from: response.body),
                            "use_dpop_nonce",
                            """
                            ORACLE (\(vector.state)): the server answered a scope \
                            question before the caller proved possession of a key. \
                            Every scope-semantic form must be met with the same \
                            nonce challenge a valid request gets.
                            """
                        )
                        challenge = response.headers[dpopNonceHeader]
                    }
                    let nonce = try XCTUnwrap(challenge, vector.state)

                    // Stage 2 — and it is still refused.
                    let proof = try makeDPoPProof(
                        key: key,
                        jwk: jwk,
                        jti: "par-oracle-\(vector.state)",
                        nonce: nonce,
                        target: try OAuthDPoPProofValidator.normalizedTarget(
                            issuer.appending(path: "oauth/par")
                        )
                    )
                    try await client.execute(
                        uri: "/oauth/par",
                        method: .post,
                        headers: formHeaders(dpop: proof),
                        body: ByteBuffer(string: vector.form)
                    ) { response in
                        XCTAssertEqual(response.status, .badRequest, vector.state)
                        XCTAssertEqual(
                            try self.errorCode(from: response.body),
                            vector.code,
                            "\(vector.state) must still be refused after the nonce"
                        )
                        let body = String(buffer: response.body)
                        XCTAssertFalse(
                            body.contains("request_uri"),
                            "\(vector.state): a refused request must not yield a request_uri"
                        )
                    }
                }

                var wrongContentType = HTTPFields()
                wrongContentType[.contentType] = "application/json"
                try await client.execute(
                    uri: "/oauth/par",
                    method: .post,
                    headers: wrongContentType,
                    body: ByteBuffer(string: validForm(state: "content-type"))
                ) { response in
                    XCTAssertEqual(response.status, .badRequest)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    XCTAssertEqual(try self.errorCode(from: response.body), "invalid_request")
                }
                let oversizedBody = String(repeating: "a", count: SwanLocalhostPARHTTP.maximumFormBytes + 1)
                try await client.execute(
                    uri: "/oauth/par",
                    method: .post,
                    headers: formHeaders(),
                    body: ByteBuffer(string: oversizedBody)
                ) { response in
                    XCTAssertEqual(response.status, .contentTooLarge)
                    XCTAssertEqual(response.headers[.cacheControl], "no-store")
                    XCTAssertEqual(try self.errorCode(from: response.body), "invalid_request")
                }
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    private func makeFixture(enablePAR: Bool = true) async throws -> (server: SwanHTTPServer, runtime: SwanOAuthRuntime, control: SQLiteControlDatabase, root: URL) {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "OAuthPARHTTPTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0xC7, count: 32)
            )
            let profile = try ProtocolProfile.load(
                from: packageRoot().appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
            )
            let par = enablePAR ? try SwanLocalhostPARConfiguration(issuer: issuer) : nil
            let server = SwanHTTPServer(
                profile: profile,
                configuration: .init(host: "127.0.0.1", port: 3_000, publicURL: issuer),
                oauthRuntime: runtime,
                localhostPARConfiguration: par
            )
            return (server, runtime, control, root)
        } catch {
            try? await control.close()
            throw error
        }
    }

    private func validForm(state: String, clientID: URL? = nil, scope: String = "atproto") -> String {
        [
            ("client_id", (clientID ?? self.clientID).absoluteString),
            ("redirect_uri", redirectURI.absoluteString),
            ("response_type", "code"),
            ("scope", scope),
            ("state", state),
            ("code_challenge", String(repeating: "a", count: 43)),
            ("code_challenge_method", "S256"),
        ].map { "\(formEncode($0.0))=\(formEncode($0.1))" }
            .joined(separator: "&")
    }

    private func formHeaders(dpop: String? = nil) -> HTTPFields {
        var headers = HTTPFields()
        headers[.contentType] = "application/x-www-form-urlencoded; charset=utf-8"
        if let dpop {
            headers[dpopHeader] = dpop
        }
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
        let signature = try P256WireSignature.sign(Data(input.utf8), using: key).base64URLEncodedString()
        return "\(input).\(signature)"
    }

    private func errorCode(from body: ByteBuffer) throws -> String {
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: body)) as? [String: Any])
        return try XCTUnwrap(object["error"] as? String)
    }

    private func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}

private let dpopHeader = HTTPField.Name("DPoP")!
private let dpopNonceHeader = HTTPField.Name("DPoP-Nonce")!

private func formEncode(_ value: String) -> String {
    value.utf8.map { byte in
        switch byte {
        case 65 ... 90, 97 ... 122, 48 ... 57, 45, 46, 95, 126:
            String(UnicodeScalar(byte))
        default:
            String(format: "%%%02X", byte)
        }
    }.joined()
}
