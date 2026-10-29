import Crypto
import Foundation
import SwanCore
import SwanSpaces
import SwanStorage
import XCTest
@testable import SwanOAuth

/// F03, part 1 — bound the revocation window by shortening what Swan mints.
///
/// A space credential names no reader and is never re-checked against
/// membership after issuance, so its lifetime *is* the revocation window. These
/// tests pin the halves of that trade separately: what Swan's authority issues
/// is short (five minutes); the generic mint default is upstream's ten minutes
/// (#5567); and what Swan mints or accepts is capped at upstream's one-hour
/// ceiling (#5567 `SPACE_CREDENTIAL_MAX_AGE_SEC`).
final class SpaceCredentialLifetimeTests: XCTestCase {
    private static let authority = "did:plc:abcdefghijklmnopqrstuvwx"

    func testIssuedCredentialLifetimeIsBoundedToFiveMinutes() throws {
        XCTAssertEqual(DurableSpaceCredentialAuthority.Configuration.defaultLifetime, 300)
        XCTAssertEqual(DurableSpaceCredentialAuthority.Configuration.standard.lifetime, 300)
        XCTAssertEqual(
            try DurableSpaceCredentialAuthority.Configuration().lifetime,
            300,
            "an unparameterised configuration must not fall back to the interop ceiling"
        )
    }

    /// The knob still spans the whole admissible range, so an operator can trade
    /// the revocation window back for fewer exchanges once it is reachable from
    /// the command line.
    func testLifetimeRemainsConfigurableUpToTheOneHourCeiling() throws {
        XCTAssertEqual(
            try DurableSpaceCredentialAuthority.Configuration(
                lifetime: PermissionedDataJWT.spaceCredentialLifetime
            ).lifetime,
            PermissionedDataJWT.spaceCredentialLifetime
        )
        XCTAssertEqual(try DurableSpaceCredentialAuthority.Configuration(lifetime: 60).lifetime, 60)
        XCTAssertThrowsError(
            try DurableSpaceCredentialAuthority.Configuration(
                lifetime: PermissionedDataJWT.spaceCredentialLifetime + 1
            )
        )
        XCTAssertThrowsError(try DurableSpaceCredentialAuthority.Configuration(lifetime: 0))
    }

    /// SWAN-AUTH-5: a per-space-type lifetime applies to that type only. The
    /// conversation policy's 60 s credentials must not shorten other spaces.
    func testSpaceTypeLifetimeAppliesOnlyToThatSpaceType() async throws {
        let conversation = try SpaceURI(
            authority: Self.authority,
            spaceType: "blue.catbird.labyrinth.conversation",
            skey: UUID().uuidString.lowercased()
        )
        let bookmarks = try SpaceURI(authority: Self.authority, spaceType: "app.bsky.bookmarks", skey: "saved")
        let key = P256.Signing.PrivateKey()
        let issuer = DurableSpaceCredentialAuthority(
            policyDirectory: PermitAllCredentialDirectory(),
            signingKeys: FixedSigningKey(authority: Self.authority, key: key),
            configuration: try .init(spaceTypeLifetimes: ["blue.catbird.labyrinth.conversation": 60])
        )
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        for (space, expected) in [(conversation, Int64(60)), (bookmarks, Int64(300))] {
            let credential = try await issuer.issueSpaceCredential(
                space: space, user: nil, authorization: .public,
                confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID, now: now
            )
            let claims = try PermissionedDataJWT.verifySpaceCredential(
                credential, publicKey: key.publicKey, expectedSpace: space, now: now
            )
            XCTAssertEqual(claims.exp - claims.iat, expected, space.spaceType)
        }
        XCTAssertThrowsError(try DurableSpaceCredentialAuthority.Configuration(spaceTypeLifetimes: ["x.y.z": 0]))
        XCTAssertThrowsError(try DurableSpaceCredentialAuthority.Configuration(
            spaceTypeLifetimes: ["x.y.z": PermissionedDataJWT.spaceCredentialLifetime + 1]
        ))
    }

    /// The ceiling is one hour on both sides (upstream #5567), and the mint
    /// default is upstream's ten minutes.
    func testCeilingIsOneHourOnMintAndVerifyAndDefaultIsTenMinutes() throws {
        XCTAssertEqual(PermissionedDataJWT.spaceCredentialLifetime, 60 * 60)
        XCTAssertEqual(PermissionedDataJWT.spaceCredentialDefaultLifetime, 10 * 60)

        let key = P256.Signing.PrivateKey()
        let space = try SpaceURI(
            authority: Self.authority,
            spaceType: "app.bsky.bookmarks",
            skey: "lifetime"
        )
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let defaulted = try PermissionedDataJWT.createSpaceCredential(
            issuer: Self.authority,
            space: space,
            key: key,
            confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
            now: now
        )
        let defaultedClaims = try PermissionedDataJWT.verifySpaceCredential(
            defaulted,
            publicKey: key.publicKey,
            expectedSpace: space,
            now: now
        )
        XCTAssertEqual(defaultedClaims.exp - defaultedClaims.iat, 600)

        let oneHourCredential = try PermissionedDataJWT.createSpaceCredential(
            issuer: Self.authority,
            space: space,
            key: key,
            confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
            now: now,
            lifetime: PermissionedDataJWT.spaceCredentialLifetime
        )
        let claims = try PermissionedDataJWT.verifySpaceCredential(
            oneHourCredential,
            publicKey: key.publicKey,
            expectedSpace: space,
            now: now.addingTimeInterval(50 * 60)
        )
        XCTAssertEqual(claims.exp - claims.iat, 3_600)

        XCTAssertThrowsError(try PermissionedDataJWT.createSpaceCredential(
            issuer: Self.authority,
            space: space,
            key: key,
            confirmationKeyID: SpaceCredentialGoldenFixtures.holderKeyID,
            now: now,
            lifetime: 2 * 60 * 60
        ), "minting above the one-hour ceiling must fail")
    }
}

private struct PermitAllCredentialDirectory: AuthorizedSimpleSpaceCredentialDirectory {
    func authorizeSimpleSpaceCredentialRead(
        space: SpaceURI, user: String?, clientID: String?, authorization: AuthorizationContext
    ) async throws {}
}

private struct FixedSigningKey: SpaceCredentialSigningKeyResolver {
    let authority: String
    let key: P256.Signing.PrivateKey
    func signingKey(for authority: String) async throws -> SpaceCredentialAuthoritySigningKey? {
        SpaceCredentialAuthoritySigningKey(authority: authority, privateKey: key)
    }
}
