import Crypto
import Foundation
import SwanCore
import SwanSpaces
import XCTest
@testable import SwanOAuth

/// F03, part 1 — bound the revocation window by shortening what Swan mints.
///
/// A space credential names no reader and is never re-checked against
/// membership after issuance, so its lifetime *is* the revocation window. These
/// tests pin the two halves of that trade separately: what Swan issues is short,
/// and what Swan accepts is unchanged, so a credential minted by the pinned
/// TypeScript authority (which uses the two-hour proposal default) still
/// verifies.
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
    func testLifetimeRemainsConfigurableUpToTheProposalCeiling() throws {
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

    /// The acceptance ceiling is an interop constant and must not move with the
    /// issuance default: the pinned TypeScript PDS mints two-hour credentials
    /// that Swan verifies.
    func testAcceptanceCeilingIsUnchangedAtTwoHours() throws {
        XCTAssertEqual(PermissionedDataJWT.spaceCredentialLifetime, 2 * 60 * 60)

        let key = P256.Signing.PrivateKey()
        let space = try SpaceURI(
            authority: Self.authority,
            spaceType: "app.bsky.bookmarks",
            skey: "lifetime"
        )
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let twoHourCredential = try PermissionedDataJWT.createSpaceCredential(
            issuer: Self.authority,
            space: space,
            key: key,
            dpopKeyThumbprint: String(repeating: "A", count: 43),
            now: now,
            lifetime: PermissionedDataJWT.spaceCredentialLifetime
        )
        let claims = try PermissionedDataJWT.verifySpaceCredential(
            twoHourCredential,
            publicKey: key.publicKey,
            expectedSpace: space,
            now: now.addingTimeInterval(90 * 60)
        )
        XCTAssertEqual(claims.exp - claims.iat, 7_200)
    }
}
