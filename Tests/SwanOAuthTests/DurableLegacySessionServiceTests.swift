import Crypto
import Foundation
import SwanAccounts
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanSQLite
import SwanStorage
import XCTest

/// The suite's own copy: the shared one in this target is `private` to its file.
private func assertThrowsAsync(
    _ expression: @autoclosure () async throws -> some Any,
    _ message: String = "expected a throw",
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail(message, file: file, line: line)
    } catch {}
}

/// App-password sessions: the token pair, its rotation, and the three
/// properties the design turns on — reuse revokes the family, scope is
/// re-derived from the app-password row rather than carried, and revoking a
/// credential ends its sessions.
final class DurableLegacySessionServiceTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let serviceDID = "did:web:swan.test"
    private let verifier =
        "$argon2id$v=19$m=65536,t=2,p=1$initialsalt$initial-precomputed-verifier"

    private struct Fixture: Sendable {
        let root: URL
        let database: SQLiteControlDatabase
        let credentials: AppPasswordCredentials
        let service: DurableLegacySessionService
    }

    private func makeFixture() async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "DurableLegacySessionServiceTests-" + UUID().uuidString)
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await database.createAccount(
            try AccountControlRegistration(
                did: did,
                canonicalHandle: "legacy.example.com",
                passwordVerifier: verifier,
                signingKey: try .init(purpose: .signing, generation: 1),
                rotationKey: try .init(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )
        let credentials = try AppPasswordCredentials()
        return Fixture(
            root: root,
            database: database,
            credentials: credentials,
            service: try DurableLegacySessionService(
                store: database,
                appPasswords: database,
                credentials: credentials,
                serviceDID: serviceDID,
                serverKey: Data(repeating: 0x2b, count: 32)
            )
        )
    }

    private func issue(
        _ fixture: Fixture,
        name: String = "Bluesky app",
        scopes: String = "atproto transition:generic",
        now: Date = Date()
    ) async throws -> (AppPasswordIssuance, LegacySessionTokens) {
        let password = try await fixture.credentials.issue(
            did: did, name: name, scopes: scopes, into: fixture.database
        )
        let tokens = try await fixture.service.issue(
            did: did, appPassword: password.record, now: now
        )
        return (password, tokens)
    }

    // MARK: - The pair

    func testIssuedAccessTokenAuthorizesAsALegacySession() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let (_, tokens) = try await issue(fixture)

        let context = try await fixture.service.authorize(accessJWT: tokens.accessJWT)
        guard case let .accountLegacySession(subject, permissions) = context else {
            return XCTFail("must produce .accountLegacySession, never .accountOAuth")
        }
        XCTAssertEqual(subject, did)
        XCTAssertTrue(permissions.hasTransitionGeneric)
    }

    /// The claim set the official client reads. `exp` in particular: the app
    /// decodes it to schedule its refresh.
    func testTheAccessTokenCarriesTheClaimsTheClientReads() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let now = Date(timeIntervalSince1970: 1_760_000_000)
        let (_, tokens) = try await issue(fixture, now: now)

        let parts = tokens.accessJWT.split(separator: ".")
        XCTAssertEqual(parts.count, 3)
        let header = try XCTUnwrap(Data(base64URLEncoded: String(parts[0])))
        let headerJSON = try XCTUnwrap(
            JSONSerialization.jsonObject(with: header) as? [String: Any]
        )
        XCTAssertEqual(headerJSON["typ"] as? String, "at+jwt")
        XCTAssertEqual(headerJSON["alg"] as? String, "HS256")

        let body = try XCTUnwrap(Data(base64URLEncoded: String(parts[1])))
        let claims = try XCTUnwrap(
            JSONSerialization.jsonObject(with: body) as? [String: Any]
        )
        XCTAssertEqual(claims["sub"] as? String, did)
        XCTAssertEqual(claims["aud"] as? String, serviceDID)
        XCTAssertEqual(claims["scope"] as? String, "com.atproto.appPass")
        XCTAssertEqual(claims["exp"] as? Int, Int(now.timeIntervalSince1970) + 120 * 60)

        // The refresh token is a DIFFERENT type. Accepting one where the other
        // is required would give a 90-day credential a 120-minute one's reach.
        let refreshHeader = try XCTUnwrap(
            Data(base64URLEncoded: String(tokens.refreshJWT.split(separator: ".")[0]))
        )
        let refreshJSON = try XCTUnwrap(
            JSONSerialization.jsonObject(with: refreshHeader) as? [String: Any]
        )
        XCTAssertEqual(refreshJSON["typ"] as? String, "refresh+jwt")
    }

    func testARefreshTokenIsNotAnAccessToken() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let (_, tokens) = try await issue(fixture)
        await assertThrowsAsync(
            try await fixture.service.authorize(accessJWT: tokens.refreshJWT)
        )
    }

    func testATamperedTokenIsRefused() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let (_, tokens) = try await issue(fixture)
        let parts = tokens.accessJWT.split(separator: ".")
        let sig = String(parts[2])
        let tampered = sig.hasSuffix("A") ? "\(sig.dropLast())B" : "\(sig.dropLast())A"
        let forged = "\(parts[0]).\(parts[1]).\(tampered)"
        await assertThrowsAsync(
            try await fixture.service.authorize(accessJWT: forged)
        )
    }

    func testAnExpiredAccessTokenIsRefused() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let now = Date(timeIntervalSince1970: 1_760_000_000)
        let (_, tokens) = try await issue(fixture, now: now)
        await assertThrowsAsync(
            try await fixture.service.authorize(
                accessJWT: tokens.accessJWT,
                now: now.addingTimeInterval(LegacySessionJWT.accessLifetime + 1)
            )
        )
    }

    /// An account-password session has no credential row to read from, so its
    /// authority is the widest the legacy surface reaches — upstream's
    /// `AuthScope.Access`. It still must not reach a space.
    func testAnAccountPasswordSessionCarriesFullLegacyAuthority() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let tokens = try await fixture.service.issue(did: did, appPassword: nil)
        let context = try await fixture.service.authorize(accessJWT: tokens.accessJWT)
        guard case let .accountLegacySession(subject, permissions) = context else {
            return XCTFail("must still be a legacy session, never .accountOAuth")
        }
        XCTAssertEqual(subject, did)
        XCTAssertTrue(permissions.allowsRepo(.init(collection: "app.bsky.feed.post", action: .create)))
        XCTAssertTrue(permissions.allowsBlob(.init(mime: "image/png")))
        XCTAssertTrue(permissions.allowsRPC(.init(lxm: "chat.bsky.convo.listConvos", aud: "did:web:x")))
        // Full LEGACY authority is not full authority: the permissioned-data
        // surface refuses `.accountLegacySession` whatever it carries.
        XCTAssertFalse(permissions.allowsSpace(
            SpaceScopeTarget(
                type: "com.example.space",
                authority: did,
                skey: "key",
                operation: .read(aggregate: false, collection: nil)
            )
        ))
    }

    /// Revoking an app password must not touch account-password sessions —
    /// their family has a NULL credential reference, so no cascade reaches it.
    func testRevokingAnAppPasswordLeavesAccountPasswordSessionsAlone() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let account = try await fixture.service.issue(did: did, appPassword: nil)
        let (scoped, _) = try await issue(fixture, name: "phone")

        try await fixture.database.revokeAppPassword(did: did, name: scoped.record.name)
        _ = try await fixture.service.authorize(accessJWT: account.accessJWT)
    }

    // MARK: - Rotation and reuse

    func testRefreshRotatesAndTheOldAccessTokenKeepsWorkingUntilItExpires() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let (_, tokens) = try await issue(fixture)
        let rotated = try await fixture.service.refresh(refreshJWT: tokens.refreshJWT)

        XCTAssertNotEqual(rotated.refreshJWT, tokens.refreshJWT)
        XCTAssertNotEqual(rotated.accessJWT, tokens.accessJWT)
        _ = try await fixture.service.authorize(accessJWT: rotated.accessJWT)
    }

    /// The security property of rotation. A second presentation means the token
    /// was captured — the legitimate client is holding the replacement — so
    /// every session descended from it ends, not just this request.
    func testReusingARotatedRefreshTokenRevokesTheWholeFamily() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let (_, tokens) = try await issue(fixture)
        let rotated = try await fixture.service.refresh(refreshJWT: tokens.refreshJWT)

        // Replay the consumed token.
        await assertThrowsAsync(
            try await fixture.service.refresh(refreshJWT: tokens.refreshJWT)
        )

        // The replacement pair is now dead too — that is the family-wide part.
        await assertThrowsAsync(
            try await fixture.service.refresh(refreshJWT: rotated.refreshJWT)
        )
        await assertThrowsAsync(
            try await fixture.service.authorize(accessJWT: rotated.accessJWT)
        )
    }

    func testDeletingASessionEndsIt() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let (_, tokens) = try await issue(fixture)
        try await fixture.service.revoke(refreshJWT: tokens.refreshJWT)
        await assertThrowsAsync(
            try await fixture.service.authorize(accessJWT: tokens.accessJWT)
        )
        // Idempotent: logging out twice is not an error.
        try await fixture.service.revoke(refreshJWT: tokens.refreshJWT)
    }

    // MARK: - Scope comes from the credential, not the session (§D5)

    /// tranquil stores scope on the session and re-mints from it, so editing an
    /// app password leaves live sessions at their old authority for the life of
    /// a 90-day refresh token. Swan reads the row, so the change lands at once.
    func testReplacingAnAppPasswordEndsSessionsBornFromTheOldOne() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let (password, tokens) = try await issue(fixture)

        let before = try await fixture.service.authorize(accessJWT: tokens.accessJWT)
        guard case let .accountLegacySession(_, wide) = before else {
            return XCTFail("expected a legacy session")
        }
        XCTAssertTrue(wide.allowsRepo(.init(collection: "app.bsky.feed.post", action: .create)))

        // Replace the credential with a narrower one under the same name.
        try await fixture.database.revokeAppPassword(did: did, name: password.record.name)
        _ = try await fixture.credentials.issue(
            did: did,
            name: password.record.name,
            scopes: "atproto",
            into: fixture.database
        )

        // The old session is gone with its credential — the family cascades on
        // the app-password row's delete.
        await assertThrowsAsync(
            try await fixture.service.authorize(accessJWT: tokens.accessJWT)
        )
    }

    /// Revoking a credential must end its sessions immediately, not at the end
    /// of the access token's 120-minute life.
    func testRevokingTheAppPasswordEndsItsSessionsAtOnce() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let (password, tokens) = try await issue(fixture)
        _ = try await fixture.service.authorize(accessJWT: tokens.accessJWT)

        try await fixture.database.revokeAppPassword(did: did, name: password.record.name)

        await assertThrowsAsync(
            try await fixture.service.authorize(accessJWT: tokens.accessJWT)
        )
        await assertThrowsAsync(
            try await fixture.service.refresh(refreshJWT: tokens.refreshJWT)
        )
    }

    /// Two sessions from two credentials are independent: revoking one must not
    /// touch the other.
    func testRevokingOneCredentialLeavesTheOthersAlone() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let (first, firstTokens) = try await issue(fixture, name: "phone")
        let (_, secondTokens) = try await issue(fixture, name: "laptop")

        try await fixture.database.revokeAppPassword(did: did, name: first.record.name)

        await assertThrowsAsync(
            try await fixture.service.authorize(accessJWT: firstTokens.accessJWT)
        )
        _ = try await fixture.service.authorize(accessJWT: secondTokens.accessJWT)
    }
}
