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

/// Credential presentation at the resource authorizer after atproto#5569:
/// `Authorization: Atproto-Space <credential>` plus an `atproto-space` HTTP
/// message signature over `authorization` and `atproto-space-audience`,
/// verified against `cnf.kid`. There is no URL/method binding, no per-request
/// replay reservation, and no nonce.
final class SpaceCredentialSignatureHTTPTests: XCTestCase, @unchecked Sendable {
    private static let origin = URL(string: "https://swan.example")!
    private static let repo = "did:plc:bcdefghijklmnopqrstuvwxy"

    func testSignatureIsReusableAcrossRequestsRoutesAndReopenedControlPlanes() async throws {
        let fixture = try await Fixture.make()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let fields = try SpaceCredentialSignatureTestSupport.headers(
                token: fixture.credential, audience: Self.repo
            )
            for _ in 0 ..< 3 {
                let grant = try await authorize(fixture, headers: fields)
                guard case let .spaceCredential(credentialGrant) = grant else {
                    return XCTFail("expected credential grant")
                }
                XCTAssertEqual(credentialGrant.space, fixture.space)
            }
            // The signature names no URL, so the request target is irrelevant.
            _ = try await authorize(fixture, headers: fields, path: "/xrpc/com.atproto.space.listRecords")
            try await fixture.control.close()

            let reopened = try await SQLiteControlDatabase(dataDirectory: fixture.root)
            do {
                let runtime = try SwanOAuthRuntime(controlStore: reopened, serverKey: Fixture.serverKey)
                let authorizer = try SwanOAuthResourceAuthorizer(
                    publicURL: Self.origin, runtime: runtime, accountControlStore: reopened
                )
                _ = try await authorizer.authorizeSpaceCredential(
                    fixture.credential, verifier: fixture.verifier,
                    request: request(headers: fields), expectedSpace: fixture.space,
                    expectedAudience: Self.repo
                )
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

    func testWrongAudienceIsBadSpaceAudienceAndBadSignaturesAreBadSpaceSignature() async throws {
        let fixture = try await Fixture.make()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            // Correctly signed, but for the authority rather than this repo.
            let authorityAudience = try SpaceCredentialSignatureTestSupport.headers(
                token: fixture.credential, audience: fixture.space.authority
            )
            await assertFailure(.badAudience, fixture, headers: authorityAudience)

            let valid = try SpaceCredentialSignatureTestSupport.headers(
                token: fixture.credential, audience: Self.repo
            )
            let audienceField = HTTPField.Name(SpaceHTTPSignature.audienceFieldName)!
            let signatureField = HTTPField.Name(SpaceHTTPSignature.signatureFieldName)!
            let inputField = HTTPField.Name(SpaceHTTPSignature.signatureInputFieldName)!

            var changedAudience = valid
            changedAudience[audienceField] = "did:plc:cdefghijklmnopqrstuvwxyz"
            await assertFailure(.badSignature, fixture, headers: changedAudience)

            var duplicateAudience = valid
            duplicateAudience[values: audienceField] = [Self.repo, Self.repo]
            await assertFailure(.badSignature, fixture, headers: duplicateAudience)

            var duplicateAuthorization = valid
            duplicateAuthorization[values: .authorization] = [
                "Atproto-Space \(fixture.credential)", "Atproto-Space \(fixture.credential)",
            ]
            await assertFailure(.badSignature, fixture, headers: duplicateAuthorization)

            var missingAudience = valid
            missingAudience[audienceField] = nil
            await assertFailure(.badSignature, fixture, headers: missingAudience)

            var missingSignature = valid
            missingSignature[signatureField] = nil
            await assertFailure(.badSignature, fixture, headers: missingSignature)

            var exchangeShaped = valid
            exchangeShaped[inputField] = "atproto-space=(\"authorization\");keyid=\"\(try SpaceCredentialSignatureTestSupport.keyID)\""
            await assertFailure(.badSignature, fixture, headers: exchangeShaped)

            let wrongKey = try SpaceCredentialSignatureTestSupport.headers(
                token: fixture.credential, audience: Self.repo, key: P256.Signing.PrivateKey()
            )
            await assertFailure(.badSignature, fixture, headers: wrongKey)

            var notADID = try SpaceCredentialSignatureTestSupport.headers(
                token: fixture.credential, audience: "repo.example.com"
            )
            notADID[audienceField] = "repo.example.com"
            await assertFailure(.badSignature, fixture, headers: notADID)
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testOnlyTheAtprotoSpaceSchemeSelectsTheCredentialVerifier() async throws {
        let fixture = try await Fixture.make()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let valid = try SpaceCredentialSignatureTestSupport.headers(
                token: fixture.credential, audience: Self.repo
            )
            // Scheme names are case-insensitive.
            var lowercase = valid
            lowercase[.authorization] = "atproto-space \(fixture.credential)"
            XCTAssertEqual(try spaceCredentialSchemeToken(from: lowercase), fixture.credential)

            // A credential smuggled under Bearer or the retired DPoP scheme is
            // refused rather than handed to OAuth or legacy-session policy.
            for scheme in ["Bearer", "DPoP"] {
                var smuggled = valid
                smuggled[.authorization] = "\(scheme) \(fixture.credential)"
                XCTAssertThrowsError(try spaceCredentialSchemeToken(from: smuggled), scheme)
            }
            // An OAuth token is not a credential presentation at all.
            var oauth = HTTPFields()
            oauth[.authorization] = "DPoP opaque-access-token"
            XCTAssertNil(try spaceCredentialSchemeToken(from: oauth))
            var duplicate = valid
            duplicate[values: .authorization] = ["Atproto-Space \(fixture.credential)", "DPoP other"]
            XCTAssertThrowsError(try spaceCredentialSchemeToken(from: duplicate)) {
                XCTAssertEqual($0 as? SpaceCredentialPresentationFailure, .badSignature)
            }
            try await fixture.control.close()
        } catch {
            try? await fixture.control.close()
            throw error
        }
    }

    func testDelegationExchangeSignatureYieldsTheConfirmationKey() async throws {
        let fixture = try await Fixture.make()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let headers = try SpaceCredentialSignatureTestSupport.exchangeHeaders(token: "delegation")
            XCTAssertEqual(
                try fixture.authorizer.verifySpaceDelegationSignature(request: request(headers: headers)),
                try SpaceCredentialSignatureTestSupport.keyID
            )
            var missingKeyID = headers
            missingKeyID[HTTPField.Name(SpaceHTTPSignature.signatureInputFieldName)!] = "atproto-space=(\"authorization\")"
            for invalid in [
                HTTPFields(),
                missingKeyID,
                try SpaceCredentialSignatureTestSupport.headers(token: "delegation", audience: Self.repo),
            ] {
                XCTAssertThrowsError(
                    try fixture.authorizer.verifySpaceDelegationSignature(request: request(headers: invalid))
                ) {
                    XCTAssertEqual($0 as? SpaceCredentialPresentationFailure, .badSignature)
                }
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
            let headers = try SpaceCredentialSignatureTestSupport.headers(
                token: fixture.credential, audience: Self.repo
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

    private func authorize(
        _ fixture: Fixture,
        headers: HTTPFields,
        path: String = "/xrpc/com.atproto.space.getRecord"
    ) async throws -> AuthorizationContext {
        guard let token = try spaceCredentialSchemeToken(from: headers) else {
            throw SwanError.unauthorized("space credential required")
        }
        return try await fixture.authorizer.authorizeSpaceCredential(
            token, verifier: fixture.verifier, request: request(headers: headers, path: path),
            expectedSpace: fixture.space, expectedAudience: Self.repo
        )
    }

    private func assertFailure(
        _ expected: SpaceCredentialPresentationFailure,
        _ fixture: Fixture,
        headers: HTTPFields,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await authorize(fixture, headers: headers)
            XCTFail("invalid credential presentation was accepted", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? SpaceCredentialPresentationFailure, expected, file: file, line: line)
        }
    }

    private func request(headers: HTTPFields, path: String = "/untrusted/path?query=ignored") -> Request {
        // Neither the hostile authority nor the incoming URI is an input to
        // the space signature.
        Request(head: HTTPRequest(
            method: .get, scheme: "https", authority: "attacker.invalid",
            path: path, headerFields: headers
        ), body: .init(buffer: ByteBuffer()))
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
            let root = FileManager.default.temporaryDirectory.appending(path: "SpaceCredentialSignatureHTTPTests-\(UUID().uuidString)")
            let control = try await SQLiteControlDatabase(dataDirectory: root)
            do {
                let authority = "did:plc:abcdefghijklmnopqrstuvwx"
                let space = try SpaceURI(authority: authority, spaceType: "com.atproto.space", skey: "signature-test")
                let authorityKey = P256.Signing.PrivateKey()
                let runtime = try SwanOAuthRuntime(controlStore: control, serverKey: serverKey)
                let keys = try PinnedSpaceCredentialPublicKeyResolver(pins: [
                    try .init(authority: authority, generation: 1, publicKey: authorityKey.publicKey),
                ])
                return Self(
                    root: root, control: control,
                    authorizer: try SwanOAuthResourceAuthorizer(
                        publicURL: SpaceCredentialSignatureHTTPTests.origin,
                        runtime: runtime, accountControlStore: control
                    ), verifier: DurableSpaceCredentialVerifier(publicKeys: keys),
                    credential: try PermissionedDataJWT.createSpaceCredential(
                        issuer: authority, space: space, key: authorityKey,
                        confirmationKeyID: SpaceCredentialSignatureTestSupport.keyID
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
