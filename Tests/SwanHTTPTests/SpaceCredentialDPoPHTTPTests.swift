import Crypto
import Foundation
import Hummingbird
import HTTPTypes
import NIOCore
import PetrelCrypto
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite
import SwanSpaces
import XCTest

final class SpaceCredentialDPoPHTTPTests: XCTestCase, @unchecked Sendable {
    private static let path = "/xrpc/com.atproto.space.getRecord"
    private static let exchangePath = "/xrpc/com.atproto.space.getSpaceCredential"
    private static let origin = URL(string: "https://swan.example")!

    func testCredentialProofUsesConfiguredOriginAndFixedRouteAndRejectsReplay() async throws {
        let fixture = try await Fixture.make()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let fields = try SpaceCredentialDPoPTestSupport.headers(
                token: fixture.credential, path: Self.path
            )
            let grant = try await authorize(fixture, headers: fields)
            guard case let .spaceCredential(credentialGrant) = grant else {
                return XCTFail("expected credential grant")
            }
            XCTAssertEqual(credentialGrant.space, fixture.space)
            await assertDenied(fixture, headers: fields)

            // The same credential remains usable with a new signed proof.
            _ = try await authorize(fixture, headers: SpaceCredentialDPoPTestSupport.headers(
                token: fixture.credential, path: Self.path
            ))
            try await fixture.control.close()

            // Replay state survives reopening the durable control plane.
            let reopened = try await SQLiteControlDatabase(dataDirectory: fixture.root)
            do {
                let runtime = try SwanOAuthRuntime(controlStore: reopened, serverKey: Fixture.serverKey)
                let authorizer = try SwanOAuthResourceAuthorizer(
                    publicURL: Self.origin, runtime: runtime, accountControlStore: reopened
                )
                do {
                    _ = try await authorizer.authorizeSpaceCredential(
                        fixture.credential, verifier: fixture.verifier,
                        request: request(headers: fields), expectedSpace: fixture.space,
                        method: "GET", fixedPath: Self.path
                    )
                    XCTFail("reopened control plane accepted a replayed proof")
                } catch {}
                try await reopened.close()
            } catch {
                try? await reopened.close()
                throw error
            }
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testCredentialRejectsBearerMissingDuplicateAndMismatchedProofs() async throws {
        let fixture = try await Fixture.make()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            var missing = HTTPFields()
            missing[.authorization] = "DPoP \(fixture.credential)"
            await assertDenied(fixture, headers: missing)

            var bearer = try SpaceCredentialDPoPTestSupport.headers(token: fixture.credential, path: Self.path)
            bearer[.authorization] = "Bearer \(fixture.credential)"
            await assertDenied(fixture, headers: bearer)

            var duplicate = try SpaceCredentialDPoPTestSupport.headers(token: fixture.credential, path: Self.path)
            let proofName = HTTPField.Name("DPoP")!
            duplicate[values: proofName] = [duplicate[proofName]!, duplicate[proofName]!]
            await assertDenied(fixture, headers: duplicate)

            var duplicateAuthorization = try SpaceCredentialDPoPTestSupport.headers(token: fixture.credential, path: Self.path)
            duplicateAuthorization[values: .authorization] = [
                "DPoP \(fixture.credential)", "DPoP \(fixture.credential)",
            ]
            await assertDenied(fixture, headers: duplicateAuthorization)

            for proof in [
                try SpaceCredentialDPoPTestSupport.proof(path: Self.path, method: "GET", token: fixture.credential, origin: "https://attacker.invalid"),
                try SpaceCredentialDPoPTestSupport.proof(path: "/xrpc/com.atproto.space.listRecords", method: "GET", token: fixture.credential),
                try SpaceCredentialDPoPTestSupport.proof(path: Self.path, method: "POST", token: fixture.credential),
                try SpaceCredentialDPoPTestSupport.proof(path: Self.path, method: "GET", token: "another-credential"),
                try SpaceCredentialDPoPTestSupport.proof(path: Self.path, method: "GET"),
                try proofWithAnotherKey(token: fixture.credential),
                "malformed-proof",
            ] {
                var fields = missing
                fields[proofName] = proof
                await assertDenied(fixture, headers: fields)
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testExchangeProofBindsHolderWithoutAccessTokenHashOrServerNonce() async throws {
        let fixture = try await Fixture.make()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let headers = try SpaceCredentialDPoPTestSupport.exchangeHeaders(token: "delegation")
            let proof = try await fixture.authorizer.validateSpaceCredentialProof(
                request: request(headers: headers), method: "POST", fixedPath: Self.exchangePath
            )
            XCTAssertEqual(proof.keyThumbprint, try SpaceCredentialDPoPTestSupport.thumbprint)

            for invalid in [
                HTTPFields(),
                try SpaceCredentialDPoPTestSupport.headers(
                    token: "delegation", path: Self.exchangePath, method: "POST"
                ),
            ] {
                do {
                    _ = try await fixture.authorizer.validateSpaceCredentialProof(
                        request: request(headers: invalid), method: "POST", fixedPath: Self.exchangePath
                    )
                    XCTFail("exchange accepted a missing proof or delegation ath")
                } catch {}
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testAccountOnlyRouteRejectsSpaceCredentialWithoutOAuthNonceChallenge() async throws {
        let fixture = try await Fixture.make()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let path = "/xrpc/com.atproto.space.createRecord"
            let headers = try SpaceCredentialDPoPTestSupport.headers(
                token: fixture.credential, path: path, method: "POST"
            )
            do {
                _ = try await fixture.authorizer.authorize(
                    request: request(headers: headers), method: "POST", fixedPath: path
                )
                XCTFail("a space credential cannot authorize an account-only route")
            } catch let failure as SwanResourceAuthorizationFailure {
                XCTAssertEqual(failure, .denied)
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    private func authorize(_ fixture: Fixture, headers: HTTPFields) async throws -> AuthorizationContext {
        guard let token = try spaceCredentialSchemeToken(from: headers) else {
            throw SwanError.unauthorized("space credential required")
        }
        return try await fixture.authorizer.authorizeSpaceCredential(
            token, verifier: fixture.verifier, request: request(headers: headers),
            expectedSpace: fixture.space, method: "GET", fixedPath: Self.path
        )
    }

    private func assertDenied(_ fixture: Fixture, headers: HTTPFields) async {
        do {
            _ = try await authorize(fixture, headers: headers)
            XCTFail("invalid credential presentation was accepted")
        } catch {}
    }

    private func request(headers: HTTPFields) -> Request {
        // Neither the hostile authority nor the unrelated incoming URI is an
        // integrity authority; only the startup origin and selected route are.
        Request(head: HTTPRequest(
            method: .get, scheme: "https", authority: "attacker.invalid",
            path: "/untrusted/path?query=ignored", headerFields: headers
        ), body: .init(buffer: ByteBuffer()))
    }

    private func proofWithAnotherKey(token: String) throws -> String {
        let key = P256.Signing.PrivateKey()
        let representation = key.publicKey.x963Representation
        let jwk = try OAuthJSONWebKey(
            x: Data(representation[1 ..< 33]).base64URLEncodedString(),
            y: Data(representation[33 ..< 65]).base64URLEncodedString()
        )
        struct Header: Encodable {
            let alg = "ES256"
            let typ = "dpop+jwt"
            let jwk: OAuthJSONWebKey
        }
        struct Claims: Encodable {
            let jti = UUID().uuidString
            let iat = Int64(Date().timeIntervalSince1970)
            let htm = "GET"
            let htu = "https://swan.example/xrpc/com.atproto.space.getRecord"
            let ath: String
        }
        let encoder = JSONEncoder()
        let header = try encoder.encode(Header(jwk: jwk)).base64URLEncodedString()
        let claims = try encoder.encode(Claims(
            ath: Data(SHA256.hash(data: Data(token.utf8))).base64URLEncodedString()
        )).base64URLEncodedString()
        let input = "\(header).\(claims)"
        return "\(input).\(try P256WireSignature.sign(Data(input.utf8), using: key).base64URLEncodedString())"
    }

    private struct Fixture {
        static let serverKey = Data(repeating: 0x48, count: 32)
        let root: URL
        let control: SQLiteControlDatabase
        let authorizer: SwanOAuthResourceAuthorizer
        let verifier: DurableSpaceCredentialVerifier
        let credential: String
        let space: SpaceURI

        static func make() async throws -> Self {
            let root = FileManager.default.temporaryDirectory.appending(path: "SpaceCredentialDPoPHTTPTests-\(UUID().uuidString)")
            let control = try await SQLiteControlDatabase(dataDirectory: root)
            do {
                let authority = "did:plc:abcdefghijklmnopqrstuvwx"
                let space = try SpaceURI(authority: authority, spaceType: "com.atproto.space", skey: "proof-test")
                let authorityKey = P256.Signing.PrivateKey()
                let runtime = try SwanOAuthRuntime(controlStore: control, serverKey: serverKey)
                let keys = try PinnedSpaceCredentialPublicKeyResolver(pins: [
                    try .init(authority: authority, generation: 1, publicKey: authorityKey.publicKey),
                ])
                return Self(
                    root: root, control: control,
                    authorizer: try SwanOAuthResourceAuthorizer(
                        publicURL: SpaceCredentialDPoPHTTPTests.origin,
                        runtime: runtime, accountControlStore: control
                    ), verifier: DurableSpaceCredentialVerifier(publicKeys: keys),
                    credential: try PermissionedDataJWT.createSpaceCredential(
                        issuer: authority, space: space, key: authorityKey,
                        dpopKeyThumbprint: SpaceCredentialDPoPTestSupport.thumbprint
                    ), space: space
                )
            } catch {
                try? await control.close()
                try? FileManager.default.removeItem(at: root)
                throw error
            }
        }
    }
}
