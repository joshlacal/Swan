import Foundation
import SwanAccounts
import SwanCore
import SwanSQLite
import SwanStorage
import XCTest

/// App-password storage, and the properties the legacy-session work depends on:
/// the secret is shown once and never again, resolution is by deterministic
/// digest, and revoking a row is what ends its sessions.
final class AppPasswordStoreSQLiteTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let otherDID = "did:plc:zyxwvutsrqponmlkjihgfedc"
    private let verifier =
        "$argon2id$v=19$m=65536,t=2,p=1$initialsalt$initial-precomputed-verifier"

    private struct Fixture: Sendable {
        let root: URL
        let database: SQLiteControlDatabase
        let credentials: AppPasswordCredentials
    }

    private func makeFixture(withOtherAccount: Bool = false) async throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "AppPasswordStoreSQLiteTests-" + UUID().uuidString)
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await database.createAccount(registration(did: did, handle: "primary.example.com"))
        if withOtherAccount {
            _ = try await database.createAccount(
                registration(did: otherDID, handle: "other.example.com")
            )
        }
        return Fixture(
            root: root,
            database: database,
            // The cheapest legal policy: these tests exercise storage, and
            // Argon2id at the production work factor would add seconds.
            credentials: try AppPasswordCredentials(policy: .interactive)
        )
    }

    private func registration(did: String, handle: String) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: verifier,
            signingKey: try .init(purpose: .signing, generation: 1),
            rotationKey: try .init(purpose: .rotation, generation: 1),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
    }

    // MARK: - Round trip

    func testIssuedPasswordResolvesBackToItsRow() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }

        let issued = try await fixture.credentials.issue(
            did: did,
            name: "Bluesky app",
            scopes: "atproto transition:generic",
            into: fixture.database
        )
        XCTAssertEqual(issued.record.name, "Bluesky app")
        XCTAssertEqual(issued.record.scopes, "atproto transition:generic")

        let resolved = try await fixture.credentials.resolve(
            did: did,
            password: issued.password,
            in: fixture.database
        )
        XCTAssertEqual(resolved?.id, issued.record.id)
        XCTAssertEqual(resolved?.scopes, "atproto transition:generic")
    }

    func testWrongPasswordResolvesToNothing() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }

        let issued = try await fixture.credentials.issue(
            did: did, name: "one", scopes: "atproto", into: fixture.database
        )
        let wrong = try await fixture.credentials.resolve(
            did: did, password: issued.password + "x", in: fixture.database
        )
        XCTAssertNil(wrong)
    }

    /// The digest is salted by DID, so a secret is useless against any other
    /// account even if the same string were somehow issued twice.
    func testAPasswordDoesNotResolveUnderAnotherAccount() async throws {
        let fixture = try await makeFixture(withOtherAccount: true)
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }

        let issued = try await fixture.credentials.issue(
            did: did, name: "one", scopes: "atproto", into: fixture.database
        )
        let crossed = try await fixture.credentials.resolve(
            did: otherDID, password: issued.password, in: fixture.database
        )
        XCTAssertNil(crossed)
    }

    // MARK: - The secret exists exactly once

    func testThePlaintextIsNeverStoredAndNeverListed() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }

        let issued = try await fixture.credentials.issue(
            did: did, name: "one", scopes: "atproto", into: fixture.database
        )

        // Not in the listing surface...
        let listed = try await fixture.database.listAppPasswords(did: did)
        XCTAssertEqual(listed.count, 1)
        XCTAssertEqual(listed[0].name, "one")
        XCTAssertFalse(
            String(describing: listed).contains(issued.password),
            "the listing must not carry the secret in any field"
        )

        // ...and not anywhere in the database file. This is the assertion that
        // would catch a future column added "for debugging".
        try await fixture.database.close()
        let files = try FileManager.default.contentsOfDirectory(
            at: fixture.root, includingPropertiesForKeys: nil
        )
        XCTAssertFalse(files.isEmpty, "positive control: the fixture must have written something")
        var found = false
        for url in files {
            guard let data = try? Data(contentsOf: url) else { continue }
            if data.range(of: Data(issued.password.utf8)) != nil { found = true }
        }
        XCTAssertFalse(found, "the plaintext app password must not appear on disk")
    }

    // MARK: - Naming and limits

    func testDuplicateNamesAreRefused() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }

        _ = try await fixture.credentials.issue(
            did: did, name: "phone", scopes: "atproto", into: fixture.database
        )
        do {
            _ = try await fixture.credentials.issue(
                did: did, name: "phone", scopes: "atproto", into: fixture.database
            )
            XCTFail("a duplicate name must be refused")
        } catch let error as AppPasswordStoreError {
            XCTAssertEqual(error, .duplicateName)
        }
    }

    /// A credential must never be issued for an account that cannot use it. The
    /// foreign key would catch a missing account but not a deactivated one.
    func testAnUnknownAccountCannotBeIssuedACredential() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }

        do {
            _ = try await fixture.credentials.issue(
                did: "did:plc:doesnotexistdoesnotexist00",
                name: "ghost",
                scopes: "atproto",
                into: fixture.database
            )
            XCTFail("an unknown account must be refused")
        } catch let error as AppPasswordStoreError {
            XCTAssertEqual(error, .unknownAccount)
        }
    }

    // MARK: - Revocation

    /// Revoking removes the row, which is what makes a live session stop
    /// refreshing: refresh re-derives its scope from this row (§D5).
    func testRevokingRemovesTheRowSoItNoLongerResolves() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }

        let issued = try await fixture.credentials.issue(
            did: did, name: "laptop", scopes: "atproto", into: fixture.database
        )
        try await fixture.database.revokeAppPassword(did: did, name: "laptop")

        let resolved = try await fixture.credentials.resolve(
            did: did, password: issued.password, in: fixture.database
        )
        XCTAssertNil(resolved)
        let listed = try await fixture.database.listAppPasswords(did: did)
        XCTAssertTrue(listed.isEmpty)
    }

    /// Idempotent, and silent about what it did — reporting "no such password"
    /// would turn revocation into a probe for which names an account holds.
    func testRevokingSomethingAbsentSucceeds() async throws {
        let fixture = try await makeFixture()
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }

        try await fixture.database.revokeAppPassword(did: did, name: "never-existed")
        try await fixture.database.revokeAppPassword(did: did, name: "never-existed")
    }

    /// The name is unique per account, not globally.
    func testTwoAccountsMayUseTheSameName() async throws {
        let fixture = try await makeFixture(withOtherAccount: true)
        defer {
            Task {
                try? await fixture.database.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }

        _ = try await fixture.credentials.issue(
            did: did, name: "phone", scopes: "atproto", into: fixture.database
        )
        _ = try await fixture.credentials.issue(
            did: otherDID, name: "phone", scopes: "atproto", into: fixture.database
        )
        let listed = try await fixture.database.listAppPasswords(did: did)
        XCTAssertEqual(listed.count, 1)
    }

    // MARK: - The generated secret

    func testGeneratedSecretsHaveTheExpectedShapeAndEntropy() {
        XCTAssertEqual(AppPasswordSecret.entropyBits, 100)
        var seen = Set<String>()
        for _ in 0 ..< 200 {
            let secret = AppPasswordSecret.generate()
            let groups = secret.split(separator: "-")
            XCTAssertEqual(groups.count, 4)
            XCTAssertTrue(groups.allSatisfy { $0.count == 5 })
            // The alphabet excludes the hand-transcription confusables.
            XCTAssertFalse(secret.contains("l"))
            XCTAssertFalse(secret.contains("1"))
            XCTAssertFalse(secret.contains("0"))
            XCTAssertFalse(secret.contains("o"))
            seen.insert(secret)
        }
        // 100 bits: a repeat in 200 draws would mean the generator is broken,
        // not unlucky.
        XCTAssertEqual(seen.count, 200)
    }
}
