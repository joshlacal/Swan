import XCTest
import SwanAccounts
import SwanCore
import SwanOAuth
@testable import SwanSQLite
import SwanSpaces
import SwanStorage

final class SwanAccountFoundationContractTests: XCTestCase {
    func testSignupPolicyAdvertisementIsDerivedFromPolicy() throws {
        XCTAssertFalse(SignupPolicy.closed.advertisesInviteCodeRequired)
        XCTAssertTrue(SignupPolicy.inviteRequired.advertisesInviteCodeRequired)
        XCTAssertFalse(SignupPolicy.openProtected.advertisesInviteCodeRequired)
    }

    func testDurableIdentifiersRejectNonDigestLookupMaterial() throws {
        XCTAssertThrowsError(try ManagementSessionID(digest: Data(repeating: 0, count: 31)))
        XCTAssertThrowsError(try LegacySessionID(digest: Data(repeating: 0, count: 33)))
        XCTAssertNoThrow(try ManagementSessionID(digest: Data(repeating: 0, count: 32)))
        XCTAssertNoThrow(try LegacySessionID(digest: Data(repeating: 0, count: 32)))
    }

    func testAuthorizationContextKeepsLegacyAndManagementDistinct() throws {
        let legacy = AuthorizationContext.accountLegacySession(
            subject: "did:plc:aaaaaaaaaaaaaaaaaaaaaa",
            sessionID: LegacySessionID(rawValue: "legacy-000000000000000000000000"),
            scopes: ["atproto"]
        )
        let management = AuthorizationContext.accountManagement(
            subject: "did:plc:aaaaaaaaaaaaaaaaaaaaaa",
            sessionID: ManagementSessionID(rawValue: "management-0000000000000000000000"),
            strength: .password
        )
        XCTAssertNotEqual(legacy, management)
        XCTAssertThrowsError(try SpaceAuthorizationPolicy.requireManagement(
            space: try SpaceURI(authority: "did:plc:aaaaaaaaaaaaaaaaaaaaaa", spaceType: "com.example.space", skey: "skey"),
            authorization: legacy,
            operation: .update
        ))
    }

    func testScopePolicyHasOnlyExplicitFullAccessSentinelAndFailsClosed() throws {
        XCTAssertEqual(ScopeGrant.fullAccessV1.rawValue, "fullAccessV1")
        XCTAssertFalse(DeclaredMethodScopePolicy.denyAll.allows(
            credential: .scopes(["atproto"]),
            method: "com.atproto.server.getSession"
        ))
        XCTAssertTrue(DeclaredMethodScopePolicy.fullAccessV1.allows(
            credential: .fullAccessV1,
            method: "com.atproto.server.getSession"
        ))
    }

    func testControlSchemaReservationsAreAdditiveAndBounded() async throws {
        XCTAssertEqual(ControlSchemaMigrationVersion.identity.rawValue, 2)
        XCTAssertEqual(ControlSchemaMigrationVersion.signup.rawValue, 3)
        XCTAssertEqual(ControlSchemaMigrationVersion.legacySessions.rawValue, 4)
        XCTAssertEqual(ControlSchemaMigrationVersion.managementSessions.rawValue, 5)
        XCTAssertEqual(ControlSchemaMigrationVersion.factors.rawValue, 6)
        let schema = SQLiteLayout.controlMigrations.joined(separator: "\n")
        for table in [
            "control_schema_migrations", "identity_bindings", "did_web_claim_transactions",
            "signup_authorizations", "signup_invites", "legacy_session_families",
            "management_sessions", "authentication_factors", "factor_challenges",
            "totp_secret_envelopes", "recovery_code_digests", "webauthn_credentials", "webauthn_challenges"
        ] {
            XCTAssertTrue(schema.contains("CREATE TABLE IF NOT EXISTS \(table)"), table)
        }
        XCTAssertTrue(schema.contains("ON DELETE CASCADE"))
        XCTAssertTrue(schema.contains("CHECK(length(session_digest) = 32)"))
        XCTAssertTrue(schema.contains("identity_bindings_account_capacity"))
        for trigger in [
            "identity_binding_history_account_capacity",
            "did_web_claim_transactions_account_capacity",
            "signup_invites_account_capacity",
            "totp_secret_envelopes_account_capacity",
            "webauthn_challenges_account_capacity"
        ] {
            XCTAssertTrue(schema.contains(trigger), trigger)
        }

        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("swan-account-foundation-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let markerRows = try await database.connection.query(
            "SELECT version FROM control_schema_migrations ORDER BY version"
        )
        XCTAssertEqual(markerRows.compactMap { $0.column("version")?.integer }, [1, 2, 3, 4, 5, 6])
        let tables = try await database.connection.query(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('identity_bindings', 'signup_authorizations', 'legacy_sessions', 'management_sessions', 'authentication_factors', 'factor_challenges', 'totp_secret_envelopes', 'recovery_code_digests', 'webauthn_credentials', 'webauthn_challenges')"
        )
        XCTAssertEqual(tables.count, 10)
        try await database.close()
    }
}
