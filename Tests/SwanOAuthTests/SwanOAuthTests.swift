import Crypto
import Foundation
import XCTest
@testable import SwanOAuth
@testable import SwanSpaces

final class SwanOAuthTests: XCTestCase {
    func testPKCEAndRefreshReuseRevokesFamily() async throws {
        XCTAssertTrue(PKCE.verifyS256(
            verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ))
        let vault = OAuthTokenVault(secret: Data(repeating: 9, count: 32))
        let pair = await vault.issue(subject: "did:plc:alice", scopes: ["atproto"])
        let rotated = try await vault.redeemRefresh(pair.refreshToken)
        let access = try await vault.validateAccess(rotated.accessToken)
        XCTAssertEqual(access.subject, "did:plc:alice")
        await XCTAssertThrowsErrorAsync(try await vault.redeemRefresh(pair.refreshToken))
        await XCTAssertThrowsErrorAsync(try await vault.validateAccess(rotated.accessToken))
    }

    func testNonceAndReplayProtection() async {
        let nonceService = DPoPNonceService(secret: Data(repeating: 1, count: 32))
        XCTAssertTrue(nonceService.isValid(nonceService.issue()))
        let replay = DPoPReplayStore()
        let firstAccepted = await replay.accept(jti: "one")
        let secondAccepted = await replay.accept(jti: "one")
        XCTAssertTrue(firstAccepted)
        XCTAssertFalse(secondAccepted)
    }

    func testSignedDelegationAndSpaceCredentialsFollowPinnedJWTClaims() throws {
        let key = P256.Signing.PrivateKey()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let space = try SpaceURI(
            authority: "did:plc:alice", spaceType: "app.bsky.bookmarks", skey: "shared"
        )
        let delegation = try PermissionedDataJWT.createDelegationToken(
            issuer: "did:plc:bob",
            audience: "did:plc:alice#atproto_space_host",
            space: space,
            key: key,
            now: now
        )
        let delegationClaims = try PermissionedDataJWT.verifyDelegationToken(
            delegation,
            publicKey: key.publicKey,
            audience: "did:plc:alice#atproto_space_host",
            now: now
        )
        XCTAssertEqual(delegationClaims.iss, "did:plc:bob")
        XCTAssertEqual(delegationClaims.sub, space.rawValue)
        XCTAssertThrowsError(try PermissionedDataJWT.verifyDelegationToken(
            delegation, publicKey: key.publicKey, audience: "did:plc:mallory#atproto_space_host", now: now
        ))

        let credential = try PermissionedDataJWT.createSpaceCredential(
            issuer: "did:plc:alice", space: space, key: key, now: now
        )
        let credentialClaims = try PermissionedDataJWT.verifySpaceCredential(credential, publicKey: key.publicKey, now: now)
        XCTAssertEqual(credentialClaims.sub, space.rawValue)
        XCTAssertThrowsError(try PermissionedDataJWT.verifySpaceCredential(
            credential, publicKey: key.publicKey, now: now.addingTimeInterval(3 * 60 * 60)
        ))
    }

    func testRemoteMetadataPolicyRejectsAllPrivateLiteralRanges() throws {
        XCTAssertThrowsError(try OAuthRemoteURLPolicy.validate(URL(string: "https://172.31.1.1/metadata")!))
        XCTAssertThrowsError(try OAuthRemoteURLPolicy.validate(URL(string: "https://169.254.169.254/latest/meta-data")!))
        XCTAssertThrowsError(try OAuthRemoteURLPolicy.validate(URL(string: "https://[fe80::1]/metadata")!))
        XCTAssertNoThrow(try OAuthRemoteURLPolicy.validate(URL(string: "https://172.32.1.1/metadata")!))
        XCTAssertNoThrow(try OAuthRemoteURLPolicy.validate(URL(string: "http://127.0.0.1:3000/metadata")!, allowLoopbackDevelopment: true))
    }
}

private func XCTAssertThrowsErrorAsync<T>(_ expression: @autoclosure () async throws -> T, file: StaticString = #filePath, line: UInt = #line) async {
    do {
        _ = try await expression()
        XCTFail("expected error", file: file, line: line)
    } catch {}
}
