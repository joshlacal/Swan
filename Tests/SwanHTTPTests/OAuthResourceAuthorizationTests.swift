import Crypto
import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import XCTest
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite
import SwanSpaces
import SwanStorage

final class OAuthResourceAuthorizationTests: XCTestCase {
    private static let subject = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let publicURL = URL(string: "https://swan.example")!
    private static let fixedPath = "/xrpc/com.atproto.space.getSpace"

    func testAuthorizesActiveAccountFromConfiguredTargetNotRequestHostOrURI() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let now = Date()
        let nonce = fixture.runtime.dpopNonceService.issue(now: now)
        let proof = try makeDPoPProof(
            key: fixture.signingKey,
            jwk: fixture.jwk,
            jti: "resource-authorize-success",
            nonce: nonce,
            method: "GET",
            target: targetText(),
            accessToken: fixture.accessToken,
            now: now
        )
        // The incoming authority and URI are intentionally hostile. A proof
        // for them would fail; success demonstrates the authorizer used only
        // its configured public URL and fixed route path.
        let request = makeRequest(
            uri: "/untrusted/path?x=1",
            authority: "attacker.invalid",
            headers: authorizationHeaders(accessToken: fixture.accessToken, proof: proof)
        )
        let context = try await fixture.authorizer.authorize(
            request: request,
            method: "GET",
            fixedPath: Self.fixedPath,
            now: now
        )
        XCTAssertEqual(context, .accountOAuth(subject: Self.subject, scopes: ["atproto", "transition:generic"]))
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.root.appending(path: "actors").path))
        try await fixture.control.close()
    }

    func testRejectsMalformedAuthorizationAndProofHeadersBeforeDurableWork() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        var duplicateAuthorization = authorizationHeaders(accessToken: fixture.accessToken)
        duplicateAuthorization[values: .authorization] = [
            "DPoP \(fixture.accessToken)",
            "DPoP \(fixture.accessToken)",
        ]
        try await assertFailure(
            .denied,
            fixture: fixture,
            request: makeRequest(headers: duplicateAuthorization)
        )

        var bearer = HTTPFields()
        bearer[.authorization] = "Bearer \(fixture.accessToken)"
        try await assertFailure(.denied, fixture: fixture, request: makeRequest(headers: bearer))

        var malformedToken = HTTPFields()
        malformedToken[.authorization] = "DPoP opaque token"
        try await assertFailure(.denied, fixture: fixture, request: makeRequest(headers: malformedToken))

        var parameterizedToken = HTTPFields()
        parameterizedToken[.authorization] = "DPoP opaque:token"
        try await assertFailure(.denied, fixture: fixture, request: makeRequest(headers: parameterizedToken))

        var oversizedToken = HTTPFields()
        oversizedToken[.authorization] = "DPoP \(String(repeating: "a", count: SwanOAuthResourceAuthorizer.maximumAccessTokenBytes + 1))"
        try await assertFailure(.denied, fixture: fixture, request: makeRequest(headers: oversizedToken))

        try await assertFailure(
            .nonceChallengeRequired,
            fixture: fixture,
            request: makeRequest(headers: authorizationHeaders(accessToken: fixture.accessToken))
        )

        var duplicateProof = authorizationHeaders(accessToken: fixture.accessToken)
        duplicateProof[values: dpopHeader] = ["a.b.c", "a.b.c"]
        try await assertFailure(
            .nonceChallengeRequired,
            fixture: fixture,
            request: makeRequest(headers: duplicateProof)
        )

        try await assertFailure(
            .nonceChallengeRequired,
            fixture: fixture,
            request: makeRequest(headers: authorizationHeaders(accessToken: fixture.accessToken, proof: "not-a-compact-jwt"))
        )
        try await fixture.control.close()
    }

    func testRejectsBadTargetMethodAndAccessTokenHashWithoutReservingReplay() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let now = Date()
        let nonce = fixture.runtime.dpopNonceService.issue(now: now)
        let jti = "resource-bad-target-not-replayed"
        let badTarget = try makeDPoPProof(
            key: fixture.signingKey,
            jwk: fixture.jwk,
            jti: jti,
            nonce: nonce,
            method: "GET",
            target: "https://attacker.invalid/xrpc/com.atproto.space.getSpace",
            accessToken: fixture.accessToken,
            now: now
        )
        try await assertFailure(
            .denied,
            fixture: fixture,
            request: makeRequest(headers: authorizationHeaders(accessToken: fixture.accessToken, proof: badTarget)),
            now: now
        )

        // A proof that did not satisfy the fixed target never reserves its
        // JTI. Reusing that JTI in a valid proof therefore succeeds once.
        let validWithSameJTI = try makeDPoPProof(
            key: fixture.signingKey,
            jwk: fixture.jwk,
            jti: jti,
            nonce: nonce,
            method: "GET",
            target: targetText(),
            accessToken: fixture.accessToken,
            now: now
        )
        _ = try await fixture.authorizer.authorize(
            request: makeRequest(headers: authorizationHeaders(accessToken: fixture.accessToken, proof: validWithSameJTI)),
            method: "GET",
            fixedPath: Self.fixedPath,
            now: now
        )

        let wrongMethod = try makeDPoPProof(
            key: fixture.signingKey,
            jwk: fixture.jwk,
            jti: "resource-wrong-method",
            nonce: nonce,
            method: "POST",
            target: targetText(),
            accessToken: fixture.accessToken,
            now: now
        )
        try await assertFailure(
            .denied,
            fixture: fixture,
            request: makeRequest(headers: authorizationHeaders(accessToken: fixture.accessToken, proof: wrongMethod)),
            now: now
        )

        let wrongHash = try makeDPoPProof(
            key: fixture.signingKey,
            jwk: fixture.jwk,
            jti: "resource-wrong-ath",
            nonce: nonce,
            method: "GET",
            target: targetText(),
            accessToken: "another-opaque-token",
            now: now
        )
        try await assertFailure(
            .denied,
            fixture: fixture,
            request: makeRequest(headers: authorizationHeaders(accessToken: fixture.accessToken, proof: wrongHash)),
            now: now
        )
        try await fixture.control.close()
    }

    func testNonceReplayAndWrongJKTAllFailWithoutDetail() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let now = Date()
        let staleNonceProof = try makeDPoPProof(
            key: fixture.signingKey,
            jwk: fixture.jwk,
            jti: "resource-bad-nonce",
            nonce: "not-issued-by-swan",
            method: "GET",
            target: targetText(),
            accessToken: fixture.accessToken,
            now: now
        )
        try await assertFailure(
            .denied,
            fixture: fixture,
            request: makeRequest(headers: authorizationHeaders(accessToken: fixture.accessToken, proof: staleNonceProof)),
            now: now
        )

        let nonce = fixture.runtime.dpopNonceService.issue(now: now)
        let replayedProof = try makeDPoPProof(
            key: fixture.signingKey,
            jwk: fixture.jwk,
            jti: "resource-replay",
            nonce: nonce,
            method: "GET",
            target: targetText(),
            accessToken: fixture.accessToken,
            now: now
        )
        _ = try await fixture.authorizer.authorize(
            request: makeRequest(headers: authorizationHeaders(accessToken: fixture.accessToken, proof: replayedProof)),
            method: "GET",
            fixedPath: Self.fixedPath,
            now: now
        )
        try await assertFailure(
            .denied,
            fixture: fixture,
            request: makeRequest(headers: authorizationHeaders(accessToken: fixture.accessToken, proof: replayedProof)),
            now: now
        )

        let otherKey = P256.Signing.PrivateKey()
        let otherJWK = try makeJWK(otherKey)
        let wrongJKT = try makeDPoPProof(
            key: otherKey,
            jwk: otherJWK,
            jti: "resource-wrong-jkt",
            nonce: nonce,
            method: "GET",
            target: targetText(),
            accessToken: fixture.accessToken,
            now: now
        )
        try await assertFailure(
            .denied,
            fixture: fixture,
            request: makeRequest(headers: authorizationHeaders(accessToken: fixture.accessToken, proof: wrongJKT)),
            now: now
        )
        try await fixture.control.close()
    }

    func testSuspendedAndDeletedAccountsCannotUseAnOtherwiseValidToken() async throws {
        let suspended = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: suspended.root) }
        let now = Date()
        _ = try await suspended.control.transitionStatus(
            did: Self.subject,
            to: .suspended,
            declaration: .init(),
            now: now
        )
        try await assertFailure(.denied, fixture: suspended, request: try validRequest(for: suspended, jti: "resource-suspended", now: now), now: now)

        let deleted = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: deleted.root) }
        _ = try await deleted.control.transitionStatus(
            did: Self.subject,
            to: .deleted,
            declaration: .init(tombstone: try AccountTombstoneMetadata(declaredAt: now, reason: "test")),
            now: now
        )
        try await assertFailure(.denied, fixture: deleted, request: try validRequest(for: deleted, jti: "resource-deleted", now: now), now: now)
        try await suspended.control.close()
        try await deleted.control.close()
    }

    func testDurableControlFailureIsTheOnlyUnavailableAuthorizationResult() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let now = Date()
        let request = try validRequest(for: fixture, jti: "resource-control-unavailable", now: now)
        try await fixture.control.close()
        try await assertFailure(.unavailable, fixture: fixture, request: request, now: now)
    }

    private func makeFixture() async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "OAuthResourceAuthorizationTests-\(UUID().uuidString)")
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let now = Date()
            _ = try await control.createAccount(
                AccountControlRegistration(
                    did: Self.subject,
                    canonicalHandle: "alice.example.com",
                    passwordVerifier: "$argon2id$v=19$m=65536,t=3,p=1$bcdefghijklmnopqrstuvw$BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
                    signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
                    rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
                    createdAt: now
                )
            )
            let runtime = try SwanOAuthRuntime(
                controlStore: control,
                serverKey: Data(repeating: 0xD4, count: 32)
            )
            let signingKey = P256.Signing.PrivateKey()
            let jwk = try makeJWK(signingKey)
            let session = try OAuthValidatedSession(
                issuer: Self.publicURL.absoluteString,
                client: OAuthResolvedClientMetadata(
                    metadata: try OAuthClientMetadata(
                        clientID: URL(string: "https://client.example/metadata")!,
                        redirectURIs: [URL(string: "https://client.example/callback")!],
                        grantTypes: ["authorization_code", "refresh_token"],
                        responseTypes: ["code"],
                        scopes: ["atproto", "transition:generic"],
                        dpopBoundAccessTokens: true
                    ),
                    keySet: nil
                ),
                redirectURI: URL(string: "https://client.example/callback")!,
                scopes: ["atproto", "transition:generic"],
                dpopProof: OAuthValidatedDPoPProof(
                    keyThumbprint: jwk.thumbprint(),
                    jwtID: "resource-issuance-\(UUID().uuidString)",
                    issuedAt: now
                ),
                now: now
            )
            let tokens = try await runtime.tokenService.issue(subject: Self.subject, session: session, now: now)
            let authorizer = try SwanOAuthResourceAuthorizer(
                publicURL: Self.publicURL,
                runtime: runtime,
                accountControlStore: control
            )
            return Fixture(
                root: root,
                control: control,
                runtime: runtime,
                authorizer: authorizer,
                signingKey: signingKey,
                jwk: jwk,
                accessToken: tokens.accessToken
            )
        } catch {
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    private func validRequest(for fixture: Fixture, jti: String, now: Date) throws -> Request {
        let nonce = fixture.runtime.dpopNonceService.issue(now: now)
        let proof = try makeDPoPProof(
            key: fixture.signingKey,
            jwk: fixture.jwk,
            jti: jti,
            nonce: nonce,
            method: "GET",
            target: targetText(),
            accessToken: fixture.accessToken,
            now: now
        )
        return makeRequest(headers: authorizationHeaders(accessToken: fixture.accessToken, proof: proof))
    }

    private func assertFailure(
        _ expected: SwanResourceAuthorizationFailure,
        fixture: Fixture,
        request: Request,
        now: Date = Date()
    ) async throws {
        do {
            _ = try await fixture.authorizer.authorize(
                request: request,
                method: "GET",
                fixedPath: Self.fixedPath,
                now: now
            )
            XCTFail("expected \(expected)")
        } catch let failure as SwanResourceAuthorizationFailure {
            XCTAssertEqual(failure, expected)
        } catch {
            XCTFail("unexpected authorization error: \(String(describing: type(of: error)))")
        }
    }

    private func authorizationHeaders(accessToken: String, proof: String? = nil) -> HTTPFields {
        var headers = HTTPFields()
        headers[.authorization] = "DPoP \(accessToken)"
        if let proof {
            headers[dpopHeader] = proof
        }
        return headers
    }

    private func makeRequest(
        uri: String = "/different-request-target",
        authority: String = "attacker.invalid",
        headers: HTTPFields
    ) -> Request {
        Request(
            head: HTTPRequest(
                method: .get,
                scheme: "https",
                authority: authority,
                path: uri,
                headerFields: headers
            ),
            body: .init(buffer: ByteBuffer())
        )
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
        method: String,
        target: String,
        accessToken: String,
        now: Date
    ) throws -> String {
        struct Header: Encodable {
            let alg = "ES256"
            let typ = OAuthDPoPProofValidator.proofType
            let jwk: OAuthJSONWebKey
        }
        struct Claims: Encodable {
            let jti: String
            let iat: Int64
            let htm: String
            let htu: String
            let nonce: String
            let ath: String
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let header = try encoder.encode(Header(jwk: jwk)).base64URLEncodedString()
        let claims = try encoder.encode(Claims(
            jti: jti,
            iat: Int64(now.timeIntervalSince1970),
            htm: method,
            htu: target,
            nonce: nonce,
            ath: Data(SHA256.hash(data: Data(accessToken.utf8))).base64URLEncodedString()
        )).base64URLEncodedString()
        let signingInput = "\(header).\(claims)"
        let signature = try P256WireSignature.sign(Data(signingInput.utf8), using: key).base64URLEncodedString()
        return "\(signingInput).\(signature)"
    }

    private func targetText() -> String {
        "https://swan.example\(Self.fixedPath)"
    }
}

private struct Fixture {
    let root: URL
    let control: SQLiteControlDatabase
    let runtime: SwanOAuthRuntime
    let authorizer: SwanOAuthResourceAuthorizer
    let signingKey: P256.Signing.PrivateKey
    let jwk: OAuthJSONWebKey
    let accessToken: String
}

private let dpopHeader = HTTPField.Name("DPoP")!
