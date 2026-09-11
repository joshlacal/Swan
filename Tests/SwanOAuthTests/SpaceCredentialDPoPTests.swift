import Crypto
import Foundation
import PetrelCrypto
import SwanCore
import SwanSQLite
import SwanSpaces
import XCTest
@testable import SwanOAuth

final class SpaceCredentialDPoPTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_750_000_000)
    private let target = URL(string: "https://repo.example/xrpc/com.atproto.space.getRepo?space=ignored#fragment")!

    func testExchangeOmitsTokenHashAndNeedsNoNonce() async throws {
        let fixture = try await Fixture()
        defer { fixture.cleanup() }
        let validator = try SpaceCredentialDPoPValidator(runtime: fixture.runtime)
        let key = P256.Signing.PrivateKey()
        let jwk = try publicJWK(key)
        let proof = try makeProof(key: key, method: "POST", target: target, now: now)
        let validated = try await validator.validate(proof, method: "POST", target: target, now: now)
        XCTAssertEqual(validated.keyThumbprint, jwk.thumbprint())
        await rejects { try await validator.validate(proof, method: "POST", target: self.target, now: self.now) }
        for hash: Any in ["delegation-hash", NSNull()] {
            let withHash = try makeProof(key: key, method: "POST", target: target, now: now, overrides: ["ath": hash])
            await rejects { try await validator.validate(withHash, method: "POST", target: self.target, now: self.now) }
        }
        try await fixture.database.close()
    }

    func testCredentialUseBindsHashKeyMethodTargetFreshnessAndReplay() async throws {
        let fixture = try await Fixture()
        defer { fixture.cleanup() }
        let validator = try SpaceCredentialDPoPValidator(runtime: fixture.runtime)
        let key = P256.Signing.PrivateKey()
        let jkt = try publicJWK(key).thumbprint()
        let credential = "credential-to-bind"
        let hash = Data(SHA256.hash(data: Data(credential.utf8))).base64URLEncodedString()
        let proof = try makeProof(key: key, method: "GET", target: target, now: now, overrides: ["ath": hash])
        _ = try await validator.validate(proof, method: "GET", target: target, credential: credential, expectedKeyThumbprint: jkt, now: now)
        await rejects { try await validator.validate(proof, method: "GET", target: self.target, credential: credential, expectedKeyThumbprint: jkt, now: self.now) }
        for overrides: [String: Any] in [
            ["ath": "wrong"], ["ath": NSNull()], ["htm": "POST"],
            ["htu": "https://other.example/xrpc/com.atproto.space.getRepo"],
            ["htu": "https://repo.example/xrpc/com.atproto.space.getRepo?space=ignored"],
            ["iat": Int64(now.timeIntervalSince1970 - 361)],
            ["iat": Int64(now.timeIntervalSince1970 + 61)], ["jti": ""],
        ] {
            let invalid = try makeProof(key: key, method: "GET", target: target, now: now, overrides: ["ath": hash].merging(overrides, uniquingKeysWith: { _, new in new }))
            await rejects { try await validator.validate(invalid, method: "GET", target: self.target, credential: credential, expectedKeyThumbprint: jkt, now: self.now) }
        }
        let missingHash = try makeProof(key: key, method: "GET", target: target, now: now)
        await rejects { try await validator.validate(missingHash, method: "GET", target: self.target, credential: credential, expectedKeyThumbprint: jkt, now: self.now) }
        let otherKey = P256.Signing.PrivateKey()
        let wrongKey = try makeProof(key: otherKey, method: "GET", target: target, now: now, overrides: ["ath": hash])
        await rejects { try await validator.validate(wrongKey, method: "GET", target: self.target, credential: credential, expectedKeyThumbprint: jkt, now: self.now) }
        try await fixture.database.close()
    }

    func testReplayReservationSurvivesReopenAndIsScopedToProofKey() async throws {
        let fixture = try await Fixture()
        defer { fixture.cleanup() }
        let key = P256.Signing.PrivateKey()
        let proof = try makeProof(key: key, method: "POST", target: target, now: now, overrides: ["jti": "shared-client-id"])
        _ = try await SpaceCredentialDPoPValidator(runtime: fixture.runtime).validate(proof, method: "POST", target: target, now: now)
        let secondKey = P256.Signing.PrivateKey()
        let second = try makeProof(key: secondKey, method: "POST", target: target, now: now, overrides: ["jti": "shared-client-id"])
        _ = try await SpaceCredentialDPoPValidator(runtime: fixture.runtime).validate(second, method: "POST", target: target, now: now)
        try await fixture.database.close()
        let reopened = try await SQLiteControlDatabase(dataDirectory: fixture.root)
        let runtime = try SwanOAuthRuntime(controlStore: reopened, serverKey: fixture.serverKey)
        await rejects { try await SpaceCredentialDPoPValidator(runtime: runtime).validate(proof, method: "POST", target: self.target, now: self.now.addingTimeInterval(1)) }
        try await reopened.close()
    }

    func testCredentialRequiresCanonicalConfirmationAndBindsValidatedProof() async throws {
        let key = P256.Signing.PrivateKey()
        let space = try SpaceURI(authority: "did:plc:abcdefghijklmnopqrstuvwx", spaceType: "app.bsky.bookmarks", skey: "test")
        let proofKey = P256.Signing.PrivateKey()
        let jkt = try publicJWK(proofKey).thumbprint()
        let token = try PermissionedDataJWT.createSpaceCredential(issuer: space.authority, space: space, key: key, dpopKeyThumbprint: jkt, now: now)
        XCTAssertEqual(try PermissionedDataJWT.inspectSpaceCredential(token).claims.cnf.jkt, jkt)
        let verifier = DurableSpaceCredentialVerifier(publicKeys: try PinnedSpaceCredentialPublicKeyResolver(pins: [try .init(authority: space.authority, generation: 1, publicKey: key.publicKey)]))
        let boundProof = OAuthValidatedDPoPProof(keyThumbprint: jkt, jwtID: "test-proof", issuedAt: now)
        _ = try await verifier.authorization(for: token, expectedSpace: space, dpopProof: boundProof, now: now)
        let wrongProof = OAuthValidatedDPoPProof(keyThumbprint: String(repeating: "A", count: 43), jwtID: "other-proof", issuedAt: now)
        await rejects { try await verifier.authorization(for: token, expectedSpace: space, dpopProof: wrongProof, now: self.now) }
        for invalid in ["", "not-a-thumbprint", jkt + "=", String(repeating: "A", count: 42) + "B"] {
            XCTAssertThrowsError(try PermissionedDataJWT.createSpaceCredential(issuer: space.authority, space: space, key: key, dpopKeyThumbprint: invalid, now: now))
        }
        let header: [String: Any] = ["alg": "ES256", "typ": PermissionedDataJWT.credentialType, "kid": "#atproto_space"]
        let claims: [String: Any] = ["iss": space.authority, "sub": space.rawValue, "iat": Int64(now.timeIntervalSince1970), "exp": Int64(now.timeIntervalSince1970 + 300), "jti": "legacy-unbound"]
        let unbound = try sign(header: header, claims: claims, key: key)
        XCTAssertThrowsError(try PermissionedDataJWT.inspectSpaceCredential(unbound))
        XCTAssertThrowsError(try PermissionedDataJWT.verifySpaceCredential(unbound, publicKey: key.publicKey, now: now))
    }
}

private struct Fixture {
    let root: URL
    let database: SQLiteControlDatabase
    let runtime: SwanOAuthRuntime
    let serverKey = Data(repeating: 0x41, count: 32)
    init() async throws {
        root = FileManager.default.temporaryDirectory.appending(path: "SpaceCredentialDPoPTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        database = try await SQLiteControlDatabase(dataDirectory: root)
        runtime = try SwanOAuthRuntime(controlStore: database, serverKey: serverKey)
    }
    func cleanup() { try? FileManager.default.removeItem(at: root) }
}

private func publicJWK(_ key: P256.Signing.PrivateKey) throws -> OAuthJSONWebKey {
    let bytes = key.publicKey.x963Representation
    return try .init(x: Data(bytes[1..<33]).base64URLEncodedString(), y: Data(bytes[33..<65]).base64URLEncodedString())
}

private func makeProof(key: P256.Signing.PrivateKey, method: String, target: URL, now: Date, overrides: [String: Any] = [:]) throws -> String {
    let jwk = try JSONSerialization.jsonObject(with: JSONEncoder().encode(publicJWK(key)))
    let claims: [String: Any] = ["jti": UUID().uuidString, "iat": Int64(now.timeIntervalSince1970), "htm": method, "htu": try OAuthDPoPProofValidator.normalizedTarget(target)]
    return try sign(header: ["alg": "ES256", "typ": "dpop+jwt", "jwk": jwk], claims: claims.merging(overrides, uniquingKeysWith: { _, new in new }), key: key)
}

private func sign(header: [String: Any], claims: [String: Any], key: P256.Signing.PrivateKey) throws -> String {
    let input = try [header, claims].map { try JSONSerialization.data(withJSONObject: $0, options: [.sortedKeys, .withoutEscapingSlashes]).base64URLEncodedString() }.joined(separator: ".")
    return try input + "." + P256WireSignature.sign(Data(input.utf8), using: key).base64URLEncodedString()
}

private func rejects<T>(_ operation: () async throws -> T, file: StaticString = #filePath, line: UInt = #line) async {
    do { _ = try await operation(); XCTFail("Expected rejection", file: file, line: line) } catch {}
}
