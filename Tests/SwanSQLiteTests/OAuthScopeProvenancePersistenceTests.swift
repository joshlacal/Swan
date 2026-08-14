import Foundation
import SQLiteNIO
import SwanCore
import SwanStorage
import XCTest

@testable import SwanSQLite

/// Durable-state tests for the scope grammar's persistence boundary.
///
/// Spec: `docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md`
/// §6.3 stage G, §6.7, §9-D20, §9-D23.
///
/// The shape of these tests is deliberate. A parse → matcher test passes with
/// the §9-D23 defect fully present, because the defect lives at the
/// persist → reload boundary; only a test that actually writes a row and reads
/// it back can see provenance being invented or destroyed.
final class OAuthScopeProvenancePersistenceTests: XCTestCase {
    private let subject = "did:plc:abcdefghijklmnopqrstuvwx"
    private let jkt = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

    /// The exact §9-D23 example: `authority` is DEFAULTED, `skey` is STATED.
    private var requestedSpaceScope: String {
        "space:app.example.doc?skey=*&action=read"
    }

    /// What mint persists after resolving `self`. Every value is now literal, so
    /// a re-parse of this string would report `authority` as stated — the
    /// "provenance invented" direction that flips the delegation fence open.
    private var resolvedSpaceScope: String {
        "space:app.example.doc?authority=\(subject)&skey=*&action=read"
    }

    // MARK: §9-D23 — provenance survives persist → reload, in both directions

    func testResolvedGrantPersistsRequestedBytesAndProvenance() async throws {
        try await withControlDatabase { database in
            // Mint's output: the effective grant is resolved, the requested
            // bytes are preserved beside it, and provenance records only what
            // the client actually wrote — `skey` and `action`, never `authority`.
            var provenance = OAuthScopeProvenance()
            provenance.record(["skey", "action"], for: self.resolvedSpaceScope)
            let binding = self.binding(
                scopes: ["atproto", self.resolvedSpaceScope],
                scopesRequested: ["atproto", self.requestedSpaceScope],
                provenance: provenance
            )
            let accessDigest = Data(repeating: 0x11, count: 32)
            try await self.mint(binding: binding, accessDigest: accessDigest, into: database)

            let reloaded = try await database.validatedAccessToken(
                accessTokenDigest: accessDigest,
                requireActiveSubject: false,
                now: Self.now.addingTimeInterval(1)
            )

            // The matcher enforces against the RESOLVED column and only it (D8).
            XCTAssertEqual(reloaded.binding.scopes, ["atproto", self.resolvedSpaceScope])
            // The refresh baseline is the REQUESTED set (D20).
            XCTAssertEqual(
                reloaded.binding.requestedScopes,
                ["atproto", self.requestedSpaceScope]
            )

            // The load-bearing assertion: `authority` is literal in the persisted
            // string and would re-parse as stated, but provenance says otherwise.
            // A fence resting on a re-parse flips false → true right here.
            let bits = try XCTUnwrap(reloaded.binding.scopeProvenance)
            XCTAssertTrue(self.resolvedSpaceScope.contains("authority="))
            XCTAssertFalse(bits.wasStated("authority", in: self.resolvedSpaceScope))
            XCTAssertTrue(bits.wasStated("skey", in: self.resolvedSpaceScope))
            XCTAssertTrue(bits.wasStated("action", in: self.resolvedSpaceScope))
        }
    }

    func testStatedDefaultEqualValueSurvivesCanonicalisation() async throws {
        // The mirror direction: canonical serialisation deletes a value equal to
        // its default, so a literally-written `skey=*` vanishes FROM THE STRING.
        // A fence requiring a stated `skey` could then never fire again.
        try await withControlDatabase { database in
            let canonicalised = "space:app.example.doc"
            var provenance = OAuthScopeProvenance()
            provenance.record(["skey"], for: canonicalised)
            let accessDigest = Data(repeating: 0x22, count: 32)
            try await self.mint(
                binding: self.binding(
                    scopes: ["atproto", canonicalised],
                    provenance: provenance
                ),
                accessDigest: accessDigest,
                into: database
            )

            let reloaded = try await database.validatedAccessToken(
                accessTokenDigest: accessDigest,
                requireActiveSubject: false,
                now: Self.now.addingTimeInterval(1)
            )
            let bits = try XCTUnwrap(reloaded.binding.scopeProvenance)
            XCTAssertFalse(canonicalised.contains("skey"))
            XCTAssertTrue(bits.wasStated("skey", in: canonicalised))
        }
    }

    // MARK: §6.7 — the NULL rule is a storage rule and a decode rule at once

    func testRequestedEqualToStoredPersistsAsNullAndReloadsTotal() async throws {
        try await withControlDatabase { database in
            // A grant with no `self` in it: requested == effective. Writing the
            // set anyway would make an empty blob and a NULL indistinguishable.
            let binding = self.binding(scopes: ["atproto"], scopesRequested: ["atproto"])
            XCTAssertNil(binding.scopesRequested, "identical requested set must collapse to NULL")

            let familyID = UUID()
            let accessDigest = Data(repeating: 0x33, count: 32)
            try await self.mint(
                binding: binding,
                familyID: familyID,
                accessDigest: accessDigest,
                into: database
            )

            let stored = try await database.connection.query(
                "SELECT scopes_requested FROM oauth_control_token_families WHERE family_id = ?",
                [.text(familyID.uuidString)]
            )
            XCTAssertEqual(stored.first?.column("scopes_requested")?.isNull, true)

            let reloaded = try await database.validatedAccessToken(
                accessTokenDigest: accessDigest,
                requireActiveSubject: false,
                now: Self.now.addingTimeInterval(1)
            )
            // `?? scopes` is the CORRECT answer for this row, not a defensive
            // shrug: it is what keeps a pre-migration family refreshing
            // unchanged.
            XCTAssertNil(reloaded.binding.scopesRequested)
            XCTAssertEqual(reloaded.binding.requestedScopes, ["atproto"])
        }
    }

    // MARK: §6.7 — the migration is additive and idempotent

    func testMigrationReAddsDroppedColumnsWithoutLosingRows() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let familyID = UUID()
        let accessDigest = Data(repeating: 0x44, count: 32)
        let seeded = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            try await mint(
                binding: binding(scopes: ["atproto"]),
                familyID: familyID,
                accessDigest: accessDigest,
                into: seeded
            )
            // Reproduce a database written by the previous binary. `CREATE TABLE
            // IF NOT EXISTS` will not re-add these; only `addColumnIfMissing`
            // can, which is the whole point of the additive migration.
            for statement in [
                "ALTER TABLE oauth_control_token_families DROP COLUMN scopes_requested",
                "ALTER TABLE oauth_control_token_families DROP COLUMN scope_provenance",
                "ALTER TABLE oauth_control_par_requests DROP COLUMN scope_provenance",
            ] {
                _ = try await seeded.connection.query(statement)
            }
            try await seeded.close()
        } catch {
            try? await seeded.close()
            throw error
        }

        // Cold start against the older schema.
        let migrated = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let columns = try await migrated.connection.query(
                "PRAGMA table_info(oauth_control_token_families)"
            )
            let names = columns.compactMap { $0.column("name")?.string }
            XCTAssertEqual(names.filter { $0 == "scopes_requested" }.count, 1)
            XCTAssertEqual(names.filter { $0 == "scope_provenance" }.count, 1)

            // The pre-migration row survives and reads as "requested == stored".
            let reloaded = try await migrated.validatedAccessToken(
                accessTokenDigest: accessDigest,
                requireActiveSubject: false,
                now: Self.now.addingTimeInterval(1)
            )
            XCTAssertNil(reloaded.binding.scopesRequested)
            XCTAssertNil(reloaded.binding.scopeProvenance)
            XCTAssertEqual(reloaded.binding.requestedScopes, ["atproto"])
            try await migrated.close()
        } catch {
            try? await migrated.close()
            throw error
        }
    }

    // MARK: §6.3 stage G — strict on INSERT, additive on read

    func testNewlyMintedGrantMustParseInFull() async throws {
        try await withControlDatabase { database in
            do {
                try await self.mint(
                    // Passes `validScope` and rides beside a good scope, exactly
                    // the shape the OR-over-the-set gate always let through. A
                    // new mint must not accept it.
                    binding: self.binding(scopes: ["atproto", "zzz.unknown:whatever"]),
                    accessDigest: Data(repeating: 0x55, count: 32),
                    into: database
                )
                XCTFail("a newly minted grant containing an unparseable scope must be rejected")
            } catch let error as OAuthControlStoreError {
                XCTAssertEqual(error, .invalidInput)
            }
        }
    }

    func testHeldUnparseableCompanionScopeStillLoads() async throws {
        // §9-D5, match layer: a HELD scope that does not parse grants nothing
        // and must not fail the read. A full re-parse on the read path would
        // permanently lock this session out — worse than failing a rotation.
        try await withControlDatabase { database in
            let familyID = UUID()
            let accessDigest = Data(repeating: 0x66, count: 32)
            try await self.mint(
                binding: self.binding(scopes: ["atproto"]),
                familyID: familyID,
                accessDigest: accessDigest,
                into: database
            )
            // Stand in for a row an older binary wrote.
            let junk = try JSONEncoder().encode(["atproto", "zzz.unknown:whatever"])
            _ = try await database.connection.query(
                "UPDATE oauth_control_token_families SET scopes = ? WHERE family_id = ?",
                [junk.sqliteData!, .text(familyID.uuidString)]
            )

            let reloaded = try await database.validatedAccessToken(
                accessTokenDigest: accessDigest,
                requireActiveSubject: false,
                now: Self.now.addingTimeInterval(1)
            )
            XCTAssertEqual(reloaded.binding.scopes, ["atproto", "zzz.unknown:whatever"])
        }
    }

    // MARK: helpers

    private static let now = Date(timeIntervalSince1970: 1_750_000_000)

    private func binding(
        scopes: Set<String>,
        scopesRequested: Set<String>? = nil,
        provenance: OAuthScopeProvenance? = nil
    ) -> OAuthClientBinding {
        OAuthClientBinding(
            issuer: "https://swan.example",
            clientID: "https://client.example/metadata.json",
            redirectURI: "https://client.example/callback",
            scopes: scopes,
            dpopJKT: jkt,
            scopesRequested: scopesRequested,
            scopeProvenance: provenance
        )
    }

    private func mint(
        binding: OAuthClientBinding,
        familyID: UUID = UUID(),
        accessDigest: Data,
        into database: SQLiteControlDatabase
    ) async throws {
        try await database.issueTokenPair(
            family: OAuthTokenFamily(
                familyID: familyID,
                subject: subject,
                binding: binding,
                expiresAt: Self.now.addingTimeInterval(3_600)
            ),
            tokens: OAuthIssuedTokenDigests(
                familyID: familyID,
                accessTokenDigest: accessDigest,
                accessExpiresAt: Self.now.addingTimeInterval(300)
            ),
            now: Self.now
        )
    }

    /// `SQLiteConnection` asserts if it deinitializes unclosed, so every path
    /// out of a test body has to close the database.
    private func withControlDatabase(
        _ body: (SQLiteControlDatabase) async throws -> Void
    ) async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            try await body(database)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "OAuthScopeProvenancePersistenceTests-\(UUID().uuidString)"
        )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }
}
