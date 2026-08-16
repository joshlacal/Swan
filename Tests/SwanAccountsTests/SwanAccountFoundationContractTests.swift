import XCTest
import SwanAccounts
import SwanCore
import SwanOAuth
@testable import SwanSQLite
import SwanSpaces
import SwanStorage

final class SwanAccountFoundationContractTests: XCTestCase {
    private let accountA = "did:plc:aaaaaaaaaaaaaaaaaaaaaa"
    private let accountB = "did:plc:bbbbbbbbbbbbbbbbbbbbbb"

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

    func testSessionIdentifierParsingThrowsInsteadOfPreconditioning() {
        XCTAssertThrowsError(try ManagementSessionID(rawValue: ""))
        XCTAssertThrowsError(try LegacySessionID(rawValue: "contains whitespace"))
        let decoder = JSONDecoder()
        XCTAssertThrowsError(try decoder.decode(ManagementSessionID.self, from: Data(#""""#.utf8)))
        XCTAssertThrowsError(try decoder.decode(LegacySessionID.self, from: Data(#""""#.utf8)))
    }

    func testMalformedValidatedValuesCannotDecode() throws {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        let malformed = Data(#"{"accountDID":"did:plc:a","digest":"AQI=","issuedAt":1}"#.utf8)
        XCTAssertThrowsError(try decoder.decode(RecoveryCodeDigest.self, from: malformed))
        XCTAssertThrowsError(try decoder.decode(TOTPSecretEnvelope.self, from: Data(#"{"factorID":"f","keyReference":"k","nonce":"AQI=","ciphertext":"AQI=","authenticationTag":"AQI="}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(FactorChallenge.self, from: Data(#"{"challengeDigest":"AQI=","accountDID":"did:plc:a","purpose":"assertion","issuedAt":2,"expiresAt":1}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(IdentityBinding.self, from: Data(#"{"accountDID":"did:plc:a","identityDID":"did:web:example.com","method":"didWeb","handle":"a","documentDigest":"AQI=","claimReceiptDigest":"AQI=","reservedKeyID":"k","state":"active"}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(DidWebClaimTransaction.self, from: Data(#"{"requestID":"r","accountDID":"did:plc:a","targetDID":"did:web:example.com","handle":"a","claimNonceDigest":"AQI=","state":"reserved","expiresAt":10}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(AppPasswordMetadata.self, from: Data(#"{"id":"p","accountDID":"did:plc:a","canonicalName":"p","scopeStrings":[],"secretDigest":"AQI=","createdAt":1}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(AuthenticationFactorMetadata.self, from: Data(#"{"id":"f","accountDID":"did:plc:a","kind":"totp","label":"f","lookupDigest":"AQI=","createdAt":1}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(WebAuthnCredentialMetadata.self, from: Data(#"{"credentialIDDigest":"AQI=","accountDID":"did:plc:a","factorID":"f","publicKeyReference":"k","signCount":0,"transports":[],"createdAt":1}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(WebAuthnChallenge.self, from: Data(#"{"challengeDigest":"AQI=","accountDID":"did:plc:a","relyingPartyID":"example.com","origin":"https://example.com","issuedAt":1,"expiresAt":2}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(AuthenticationStrength.self, from: Data(#"{"kind":"unknown"}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(SignupAuthorization.self, from: Data(#"{"id":"signup-1","requestID":"r","policy":"closed","handle":"a","clientIPBucketDigest":"AQI=","state":"issued","issuedAt":1,"expiresAt":2}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(SignupInvite.self, from: Data(#"{"digest":"AQI=","issuedAt":1}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(LegacySessionFamilyMetadata.self, from: Data(#"{"familyID":"f","accountDID":"did:plc:a","createdAt":2,"expiresAt":1}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(LegacySessionMetadata.self, from: Data(#"{"sessionID":"legacy-1","familyID":"f","accountDID":"did:plc:a","scopeStrings":[],"issuedAt":1,"expiresAt":2,"replacedByDigest":"AQI="}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(ManagementSessionMetadata.self, from: Data(#"{"sessionID":"management-1","accountDID":"did:plc:a","issuedAt":2,"idleExpiresAt":1,"absoluteExpiresAt":3,"strength":{"kind":"password"}}"#.utf8)))
    }

    func testAuthorizationContextKeepsLegacyAndManagementDistinct() throws {
        let legacy = AuthorizationContext.accountLegacySession(
            subject: "did:plc:aaaaaaaaaaaaaaaaaaaaaa",
            sessionID: try LegacySessionID(rawValue: "legacy-000000000000000000000000"),
            scopes: ["atproto"]
        )
        let management = AuthorizationContext.accountManagement(
            subject: "did:plc:aaaaaaaaaaaaaaaaaaaaaa",
            sessionID: try ManagementSessionID(rawValue: "management-0000000000000000000000"),
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
        XCTAssertFalse(DeclaredMethodScopePolicy.fullAccessV1.allows(
            credential: .fullAccessV1,
            method: "not-an-nsid"
        ))
    }

    func testValidStepUpFactoryRejectsMismatchedFactor() throws {
        XCTAssertThrowsError(try AuthenticationStrength.stepUp(
            base: .passwordPlusTOTP,
            factor: .passkey,
            verifiedAt: Date()
        ))
        XCTAssertNoThrow(try AuthenticationStrength.stepUp(
            base: .passwordPlusTOTP,
            factor: .totp,
            verifiedAt: Date()
        ))
    }

    func testSignupFinalizationIsOneAtomicBundle() throws {
        let id = try SignupAuthorizationID(rawValue: "signup-1")
        let sessionID = try ManagementSessionID(rawValue: "management-1")
        let session = try ManagementSessionMetadata(
            sessionID: sessionID,
            accountDID: accountA,
            issuedAt: Date(timeIntervalSince1970: 10),
            idleExpiresAt: Date(timeIntervalSince1970: 20),
            absoluteExpiresAt: Date(timeIntervalSince1970: 30),
            strength: .password
        )
        XCTAssertNoThrow(try SignupFinalizationRequest(
            authorizationID: id,
            accountDID: accountA,
            handle: "alice.example",
            identityDID: accountA,
            reservedKeyID: "key-1",
            managementSession: session,
            sessionDigest: Data(repeating: 1, count: 32),
            csrfDigest: Data(repeating: 2, count: 32),
            emailProofDigest: Data(repeating: 3, count: 32),
            inviteDigest: Data(repeating: 4, count: 32),
            preAuthCSRFDigest: Data(repeating: 5, count: 32),
            idempotencyKey: "signup-1"
        ))
    }

    func testWebAuthnSignCountRequiresCompareAndSwap() throws {
        XCTAssertThrowsError(try WebAuthnSignCountUpdate(
            credentialIDDigest: Data(repeating: 1, count: 32),
            accountDID: accountA,
            expectedCurrent: 4,
            proposed: 4,
            now: Date()
        ))
        XCTAssertNoThrow(try WebAuthnSignCountUpdate(
            credentialIDDigest: Data(repeating: 1, count: 32),
            accountDID: accountA,
            expectedCurrent: 4,
            proposed: 5,
            now: Date()
        ))
    }

    func testLegacyRotationCarriesLineageAndReuseOutcome() throws {
        let family = try LegacySessionFamilyMetadata(
            familyID: "family-1", accountDID: accountA, appPasswordID: nil,
            createdAt: Date(timeIntervalSince1970: 1),
            expiresAt: Date(timeIntervalSince1970: 10)
        )
        let old = try LegacySessionMetadata(
            sessionID: try LegacySessionID(rawValue: "legacy-old"), familyID: family.familyID,
            accountDID: accountA, appPasswordID: nil, scopeStrings: ["atproto"],
            issuedAt: Date(timeIntervalSince1970: 1), expiresAt: Date(timeIntervalSince1970: 10)
        )
        XCTAssertEqual(old.familyID, family.familyID)
        let detectedAt = Date(timeIntervalSince1970: 5)
        XCTAssertEqual(LegacySessionRotationOutcome.reuseDetected(familyID: family.familyID, detectedAt: detectedAt), .reuseDetected(familyID: family.familyID, detectedAt: detectedAt))
    }

    func testDidWebCommitRequiresExactReservationAndIdempotencyMatch() throws {
        let transaction = try DidWebClaimTransaction(
            requestID: "claim-1", accountDID: accountA, targetDID: "did:web:example.com",
            handle: "alice.example", claimNonceDigest: Data(repeating: 1, count: 32),
            requestedDocumentDigest: Data(repeating: 2, count: 32), state: .committing,
            expiresAt: Date(timeIntervalSinceNow: 60), stepUpReceiptDigest: Data(repeating: 3, count: 32),
            reservedKeyID: "key-1", claimReceiptDigest: Data(repeating: 4, count: 32)
        )
        XCTAssertNoThrow(try DidWebClaimCommitRequest(
            transaction: transaction, accountDID: accountA, targetDID: "did:web:example.com",
            handle: "alice.example", documentDigest: Data(repeating: 2, count: 32),
            reservedKeyID: "key-1", claimNonceDigest: Data(repeating: 1, count: 32),
            claimReceiptDigest: Data(repeating: 4, count: 32), idempotencyKey: "claim-1", now: Date()
        ))
        XCTAssertThrowsError(try DidWebClaimCommitRequest(
            transaction: transaction, accountDID: accountB, targetDID: "did:web:example.com",
            handle: "alice.example", documentDigest: Data(repeating: 2, count: 32),
            reservedKeyID: "key-1", claimNonceDigest: Data(repeating: 1, count: 32),
            claimReceiptDigest: Data(repeating: 4, count: 32), idempotencyKey: "claim-1", now: Date()
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
        let foreignKeys = try await database.connection.query("PRAGMA foreign_keys")
        XCTAssertEqual(foreignKeys.first?.column("foreign_keys")?.integer, 1)

        try await database.connection.query("INSERT INTO accounts(did, handle, status, created_at) VALUES ('\(accountA)', 'alice.example', 'active', 1), ('\(accountB)', 'bob.example', 'active', 1)")
        try await database.connection.query("INSERT INTO identity_bindings(account_did, identity_did, method, handle, state) VALUES ('\(accountA)', '\(accountA)', 'plc', 'alice.example', 'active')")
        do {
            try await database.connection.query("UPDATE identity_bindings SET account_did = '\(accountB)' WHERE account_did = '\(accountA)'")
            XCTFail("account ownership must be immutable")
        } catch { }
        try await database.connection.query("INSERT INTO did_web_claim_transactions(request_id, account_did, target_did, handle, claim_nonce_digest, state, expires_at) VALUES ('claim-ownership', '\(accountA)', 'did:web:example.com', 'alice.example', randomblob(32), 'reserved', 100)")
        do {
            try await database.connection.query("UPDATE did_web_claim_transactions SET account_did = NULL WHERE request_id = 'claim-ownership'")
            XCTFail("claim ownership must not be cleared")
        } catch { }
        try await database.connection.query("INSERT INTO signup_authorizations(authorization_id, request_id, account_did, policy, handle, client_ip_bucket_digest, state, issued_at, expires_at) VALUES ('auth-ownership', 'request-ownership', '\(accountA)', 'closed', 'alice.example', randomblob(32), 'issued', 1, 100)")
        do {
            try await database.connection.query("UPDATE signup_authorizations SET account_did = NULL WHERE authorization_id = 'auth-ownership'")
            XCTFail("signup authorization ownership must not be cleared")
        } catch { }
        try await database.connection.query("INSERT INTO signup_invites(invite_digest, issued_at, redemption_account_did) VALUES (x'0202020202020202020202020202020202020202020202020202020202020202', 1, '\(accountA)')")
        do {
            try await database.connection.query("UPDATE signup_invites SET redemption_account_did = NULL WHERE invite_digest = x'0202020202020202020202020202020202020202020202020202020202020202'")
            XCTFail("invite redemption ownership must not be cleared")
        } catch { }
        try await database.connection.query("INSERT INTO app_passwords(app_password_id, account_did, canonical_name, scope_strings, secret_digest, created_at) VALUES ('app-a', '\(accountA)', 'primary', x'00', randomblob(32), 1)")
        do {
            try await database.connection.query("INSERT INTO legacy_session_families(family_id, account_did, app_password_id, created_at, expires_at) VALUES ('family-b', '\(accountB)', 'app-a', 1, 100)")
            XCTFail("legacy family must match app-password account")
        } catch { }
        try await database.connection.query("INSERT INTO legacy_session_families(family_id, account_did, app_password_id, created_at, expires_at) VALUES ('family-a', '\(accountA)', 'app-a', 1, 100)")
        do {
            try await database.connection.query("INSERT INTO legacy_sessions(session_digest, family_id, account_did, app_password_id, scope_strings, issued_at, expires_at) VALUES (randomblob(32), 'family-a', '\(accountB)', 'app-a', x'00', 1, 100)")
            XCTFail("legacy session must match family and app-password account")
        } catch { }
        try await database.connection.query("INSERT INTO authentication_factors(factor_id, account_did, kind, label, lookup_digest, created_at) VALUES ('factor-a', '\(accountA)', 'totp', 'a', zeroblob(32), 1), ('factor-b', '\(accountB)', 'totp', 'b', randomblob(32), 1)")
        do {
            try await database.connection.query("INSERT INTO factor_challenges(challenge_digest, account_did, factor_id, purpose, issued_at, expires_at) VALUES (randomblob(32), '\(accountA)', 'factor-b', 'assertion', 1, 2)")
            XCTFail("factor challenge must match factor account")
        } catch { }
        do {
            try await database.connection.query("INSERT INTO webauthn_credentials(credential_id_digest, account_did, factor_id, public_key_reference, sign_count, transports, created_at) VALUES (randomblob(32), '\(accountA)', 'factor-b', 'key', 0, x'00', 1)")
            XCTFail("WebAuthn credential must match factor account")
        } catch { }
        try await database.connection.query("INSERT INTO webauthn_credentials(credential_id_digest, account_did, factor_id, public_key_reference, sign_count, transports, created_at) VALUES (x'0101010101010101010101010101010101010101010101010101010101010101', '\(accountB)', 'factor-b', 'key', 4, x'00', 1)")
        do {
            try await database.connection.query("INSERT INTO webauthn_challenges(challenge_digest, account_did, credential_id_digest, relying_party_id, origin, issued_at, expires_at) VALUES (randomblob(32), '\(accountA)', x'0101010101010101010101010101010101010101010101010101010101010101', 'example.com', 'https://example.com', 1, 2)")
            XCTFail("WebAuthn challenge must match credential account")
        } catch { }
        do {
            try await database.connection.query("UPDATE webauthn_credentials SET sign_count = 3 WHERE credential_id_digest = x'0101010101010101010101010101010101010101010101010101010101010101'")
            XCTFail("WebAuthn sign count rollback must be rejected")
        } catch { }
        try await database.connection.query("DELETE FROM accounts WHERE did = '\(accountA)'")
        let cascaded = try await database.connection.query("SELECT (SELECT COUNT(*) FROM identity_bindings WHERE account_did = '\(accountA)') AS bindings, (SELECT COUNT(*) FROM authentication_factors WHERE account_did = '\(accountA)') AS factors")
        XCTAssertEqual(cascaded.first?.column("bindings")?.integer, 0)
        XCTAssertEqual(cascaded.first?.column("factors")?.integer, 0)
        try await database.connection.query("BEGIN IMMEDIATE")
        try await database.connection.query("INSERT INTO control_schema_migrations(version, applied_at) VALUES (99, 1)")
        try await database.connection.query("ROLLBACK")
        let rolledBackMarkers = try await database.connection.query("SELECT version FROM control_schema_migrations WHERE version = 99")
        XCTAssertTrue(rolledBackMarkers.isEmpty)
        try await database.close()
        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        let reopenedMarkers = try await reopened.connection.query("SELECT version FROM control_schema_migrations ORDER BY version")
        XCTAssertEqual(reopenedMarkers.compactMap { $0.column("version")?.integer }, [1, 2, 3, 4, 5, 6])
        try await reopened.close()
    }
}
