import Crypto
import Foundation
import PetrelCrypto
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage
import XCTest

final class TypeScriptSpaceNotificationContractTests: XCTestCase {
    func testPinnedTypeScriptES256KNotifyWriteGoldenAndDirectWriterContract() async throws {
        let fixture = try loadFixture()
        let inspection = try SpaceServiceJWT.inspect(fixture.token)
        XCTAssertEqual(inspection.algorithm, "ES256K")
        XCTAssertEqual(inspection.claims.iss, fixture.issuer)
        XCTAssertEqual(inspection.claims.aud, fixture.audience)
        XCTAssertEqual(inspection.claims.lxm, fixture.method)
        XCTAssertEqual(inspection.claims.jti, fixture.eventID)

        let publicKey = try XCTUnwrap(Data(base64URLEncoded: fixture.publicKey))
        let verifier = DurableSpaceServiceAuthenticationVerifier(
            publicKeys: try PinnedSpaceServicePublicKeyResolver(pins: [
                try .init(issuer: fixture.issuer, generation: 1, secp256k1PublicKey: publicKey),
            ])
        )
        let space = try SpaceURI(authority: fixture.audience, spaceType: "app.bsky.bookmarks", skey: "self")
        let expectedDigest = SpaceServiceRequestDigest.write(
            space: space,
            repository: fixture.issuer,
            revision: "3jzk76w5wzs2a",
            commitment: Data(repeating: 0x24, count: 32)
        )

        // The pinned upstream token is unbound (carries no req claim), so it must be
        // rejected when the route requires a bound request body digest.
        do {
            _ = try await verifier.authenticate(
                fixture.token,
                expectedAudience: fixture.audience,
                expectedMethod: fixture.method,
                expectedRequestBodyDigest: expectedDigest,
                now: Date(timeIntervalSince1970: 1_750_000_010)
            )
            XCTFail("expected unbound pinned typescript token to be rejected when expected digest is required")
        } catch let error as SwanError {
            XCTAssertEqual(error, .unauthorized("service authentication is invalid"))
        }

        // Baseline inspection/verification without expected digest succeeds.
        let verified = try await verifier.authenticate(
            fixture.token,
            expectedAudience: fixture.audience,
            expectedMethod: fixture.method,
            now: Date(timeIntervalSince1970: 1_750_000_010)
        )
        XCTAssertEqual(verified.issuer, fixture.issuer)
        XCTAssertEqual(verified.audience, fixture.audience)
        XCTAssertEqual(verified.eventID, fixture.eventID)
        XCTAssertNil(verified.requestBodyDigest)

        // This is the shape Swan emits to a pinned TypeScript authority: the
        // local writer is issuer, the configured authority service identity is
        // audience, and `lxm` binds the XRPC method. It is intentionally not
        // an authority-signed recipient fanout.
        let swanKey = P256.Signing.PrivateKey()
        let swanToken = try SpaceServiceJWT.create(
            issuer: fixture.issuer,
            audience: fixture.audience,
            method: fixture.method,
            eventID: "swan-direct-writer-contract",
            requestBodyDigest: expectedDigest,
            key: swanKey,
            now: Date(timeIntervalSince1970: 1_750_000_000)
        )
        let swanInspection = try SpaceServiceJWT.inspect(swanToken)
        XCTAssertEqual(swanInspection.algorithm, "ES256")
        XCTAssertEqual(swanInspection.claims.iss, fixture.issuer)
        XCTAssertEqual(swanInspection.claims.aud, fixture.audience)
        XCTAssertEqual(swanInspection.claims.lxm, fixture.method)
        XCTAssertEqual(swanInspection.claims.jti, "swan-direct-writer-contract")
        XCTAssertEqual(swanInspection.claims.requestBodyDigest, expectedDigest)

        let swanVerifier = DurableSpaceServiceAuthenticationVerifier(
            publicKeys: try PinnedSpaceServicePublicKeyResolver(pins: [
                try .init(issuer: fixture.issuer, generation: 1, publicKey: swanKey.publicKey),
            ])
        )
        let swanVerified = try await swanVerifier.authenticate(
            swanToken,
            expectedAudience: fixture.audience,
            expectedMethod: fixture.method,
            expectedRequestBodyDigest: expectedDigest,
            now: Date(timeIntervalSince1970: 1_750_000_010)
        )
        XCTAssertEqual(swanVerified.issuer, fixture.issuer)
        XCTAssertEqual(swanVerified.audience, fixture.audience)
        XCTAssertEqual(swanVerified.requestBodyDigest, expectedDigest)

        // The checked-in fixture records the three source-level requirements
        // from the pinned handler. If the ignored source cache is present (as
        // it is in interop CI), also pin that evidence to the exact source.
        let sourceURL = packageRoot()
            .appending(path: ".interop-cache/atproto-\(fixture.referenceCommit)")
            .appending(path: fixture.source)
        if FileManager.default.fileExists(atPath: sourceURL.path) {
            let source = try String(contentsOf: sourceURL, encoding: .utf8)
            for requirement in fixture.sourceRequirements {
                XCTAssertTrue(source.contains(requirement), "pinned source is missing \(requirement)")
            }
            // The pinned generic service-JWT code uses the signing key's
            // declared algorithm and forwards the header algorithm into
            // `verifySignature`; P-256 is a supported `ES256` keypair. This
            // is the TypeScript-side contract evidence for the Swan-generated
            // direct writer token above, without pretending an unconfigured
            // local fixture is a running reference PDS.
            let root = packageRoot().appending(path: ".interop-cache/atproto-\(fixture.referenceCommit)")
            let serviceJWTSource = try String(
                contentsOf: root.appending(path: "packages/xrpc-server/src/auth.ts"),
                encoding: .utf8
            )
            XCTAssertTrue(serviceJWTSource.contains("alg: keypair.jwtAlg"))
            XCTAssertTrue(serviceJWTSource.contains("jwtAlg: alg"))
            let cryptoConstants = try String(
                contentsOf: root.appending(path: "packages/crypto/src/const.ts"),
                encoding: .utf8
            )
            XCTAssertTrue(cryptoConstants.contains("P256_JWT_ALG = 'ES256'"))
        }
    }

    private func loadFixture() throws -> TypeScriptNotifyWriteFixture {
        let url = try XCTUnwrap(Bundle.module.url(
            forResource: "pinned-typescript-notify-write",
            withExtension: "json",
            subdirectory: "Fixtures"
        ))
        return try JSONDecoder().decode(TypeScriptNotifyWriteFixture.self, from: Data(contentsOf: url))
    }
}

private struct TypeScriptNotifyWriteFixture: Decodable {
    let referenceCommit: String
    let source: String
    let sourceRequirements: [String]
    let issuer: String
    let audience: String
    let method: String
    let eventID: String
    let publicKey: String
    let token: String
}

private func packageRoot() -> URL {
    URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
}
