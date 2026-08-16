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
        XCTAssertThrowsError(try decoder.decode(IdentityBinding.self, from: Data(#"{"accountDID":"did:plc:a","identityDID":"did:web:example.com","method":"didWeb","handle":"a","state":"active"}"#.utf8)))
    }

    func testIdentityBindingRequiresMethodSpecificClaimMaterial() throws {
        XCTAssertThrowsError(try IdentityBinding(
            accountDID: accountA, identityDID: "did:web:example.com", method: .didWeb,
            handle: "alice.example", documentDigest: nil,
            claimReceiptDigest: Data(repeating: 1, count: 32), reservedKeyID: "key-1"
        ))
        XCTAssertThrowsError(try IdentityBinding(
            accountDID: accountA, identityDID: accountA, method: .plc,
            handle: "alice.example", documentDigest: Data(repeating: 1, count: 32)
        ))
        XCTAssertNoThrow(try IdentityBinding(
            accountDID: accountA, identityDID: "did:web:example.com", method: .didWeb,
            handle: "alice.example", documentDigest: Data(repeating: 1, count: 32),
            claimReceiptDigest: Data(repeating: 2, count: 32), reservedKeyID: "key-1"
        ))
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
        let revokedAt = Date(timeIntervalSince1970: 6)
        XCTAssertEqual(
            LegacySessionRotationOutcome.reuseDetectedAndFamilyRevoked(
                familyID: family.familyID, detectedAt: detectedAt, revokedAt: revokedAt
            ),
            .reuseDetectedAndFamilyRevoked(
                familyID: family.familyID, detectedAt: detectedAt, revokedAt: revokedAt
            )
        )
        XCTAssertThrowsError(try LegacySessionFamilyMetadata(
            familyID: family.familyID, accountDID: accountA, appPasswordID: nil,
            createdAt: Date(timeIntervalSince1970: 1), expiresAt: Date(timeIntervalSince1970: 10),
            reuseDetectedAt: detectedAt
        ))
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

    func testDidWebFailedClaimCanRetryBeforeExpiryAndCommitDerivesBinding() throws {
        let transaction = try DidWebClaimTransaction(
            requestID: "claim-retry", accountDID: accountA, targetDID: "did:web:example.com",
            handle: "alice.example", claimNonceDigest: Data(repeating: 1, count: 32),
            requestedDocumentDigest: Data(repeating: 2, count: 32), state: .failed,
            expiresAt: Date(timeIntervalSinceNow: 60), reservedKeyID: "key-1",
            claimReceiptDigest: Data(repeating: 4, count: 32)
        )
        let pending = try transaction.transition(to: .pendingValidation, now: Date())
        XCTAssertEqual(pending.state, .pendingValidation)
        let committing = try pending.transition(to: .committing, now: Date())
        let request = try DidWebClaimCommitRequest(
            transaction: committing, accountDID: accountA, targetDID: "did:web:example.com",
            handle: "alice.example", documentDigest: Data(repeating: 2, count: 32),
            reservedKeyID: "key-1", claimNonceDigest: Data(repeating: 1, count: 32),
            claimReceiptDigest: Data(repeating: 4, count: 32), idempotencyKey: "claim-retry", now: Date()
        )
        XCTAssertEqual(request.identityBinding.method, .didWeb)
        XCTAssertEqual(request.identityBinding.documentDigest, Data(repeating: 2, count: 32))
        XCTAssertEqual(request.identityBinding.claimReceiptDigest, Data(repeating: 4, count: 32))
        XCTAssertEqual(request.identityBinding.reservedKeyID, "key-1")
    }

    func testControlSchemaReservationsAreAdditiveAndBounded() async throws {
        XCTAssertEqual(ControlSchemaMigrationVersion.identity.rawValue, 2)
        XCTAssertEqual(ControlSchemaMigrationVersion.signup.rawValue, 3)
        XCTAssertEqual(ControlSchemaMigrationVersion.legacySessions.rawValue, 4)
        XCTAssertEqual(ControlSchemaMigrationVersion.managementSessions.rawValue, 5)
        XCTAssertEqual(ControlSchemaMigrationVersion.factors.rawValue, 6)
        XCTAssertEqual(ControlSchemaMigrationVersion.hardening.rawValue, 7)
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
        XCTAssertEqual(markerRows.compactMap { $0.column("version")?.integer }, [1, 2, 3, 4, 5, 6, 7])
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
        XCTAssertEqual(reopenedMarkers.compactMap { $0.column("version")?.integer }, [1, 2, 3, 4, 5, 6, 7])
        try await reopened.close()
    }

    func testHardeningMigrationUpgradesOldFoundationFixtureAndPreservesRows() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("swan-account-foundation-v7-old-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let initial = try await SQLiteControlDatabase(dataDirectory: root)
        try await initial.connection.query("INSERT INTO accounts(did, handle, status, created_at) VALUES ('\(accountA)', 'alice.example', 'active', 1), ('\(accountB)', 'bob.example', 'active', 1)")
        try await initial.connection.query("PRAGMA foreign_keys = OFF")
        for table in [
            "webauthn_challenges", "webauthn_credentials", "recovery_code_digests",
            "totp_secret_envelopes", "factor_challenges", "authentication_factors",
            "management_sessions", "legacy_sessions", "legacy_session_families",
            "app_passwords", "signup_invites", "signup_authorizations",
            "did_web_claim_transactions", "identity_binding_history", "identity_bindings"
        ] {
            try await initial.connection.query("DROP TABLE IF EXISTS \(table)")
        }
        try await initial.connection.query("""
            CREATE TABLE identity_bindings (
                account_did TEXT PRIMARY KEY REFERENCES accounts(did) ON DELETE CASCADE,
                identity_did TEXT NOT NULL UNIQUE, method TEXT NOT NULL, handle TEXT NOT NULL,
                document_digest BLOB, last_validated_at INTEGER, grace_expires_at INTEGER, state TEXT NOT NULL
            )
            """)
        try await initial.connection.query("""
            CREATE TABLE identity_binding_history (
                account_did TEXT NOT NULL, replaced_at INTEGER NOT NULL, identity_did TEXT NOT NULL,
                document_digest BLOB, claim_receipt_digest BLOB, reserved_key_id TEXT,
                PRIMARY KEY(account_did, replaced_at)
            )
            """)
        try await initial.connection.query("""
            CREATE TABLE did_web_claim_transactions (
                request_id TEXT PRIMARY KEY, account_did TEXT REFERENCES accounts(did) ON DELETE CASCADE,
                target_did TEXT NOT NULL, handle TEXT NOT NULL, claim_nonce_digest BLOB NOT NULL,
                requested_document_digest BLOB, state TEXT NOT NULL, expires_at INTEGER NOT NULL,
                step_up_receipt_digest BLOB
            )
            """)
        try await initial.connection.query("""
            CREATE TABLE signup_authorizations (
                authorization_id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE,
                account_did TEXT REFERENCES accounts(did) ON DELETE CASCADE, policy TEXT NOT NULL,
                handle TEXT NOT NULL, email TEXT, identity_did TEXT, email_proof_digest BLOB,
                invite_digest BLOB, client_ip_bucket_digest BLOB NOT NULL, state TEXT NOT NULL,
                issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, lease_expires_at INTEGER
            )
            """)
        try await initial.connection.query("CREATE TABLE signup_invites (invite_digest BLOB PRIMARY KEY, issued_at INTEGER NOT NULL, expires_at INTEGER, redeemed_at INTEGER, redemption_account_did TEXT)")
        try await initial.connection.query("CREATE TABLE app_passwords (app_password_id TEXT PRIMARY KEY, account_did TEXT NOT NULL, canonical_name TEXT NOT NULL, scope_strings BLOB NOT NULL, secret_digest BLOB NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER, revoked_at INTEGER)")
        try await initial.connection.query("CREATE TABLE legacy_session_families (family_id TEXT PRIMARY KEY, account_did TEXT NOT NULL, app_password_id TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER)")
        try await initial.connection.query("CREATE TABLE legacy_sessions (session_digest BLOB PRIMARY KEY, family_id TEXT NOT NULL, account_did TEXT NOT NULL, app_password_id TEXT, scope_strings BLOB NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER)")
        try await initial.connection.query("CREATE TABLE management_sessions (session_digest BLOB PRIMARY KEY, account_did TEXT NOT NULL, csrf_digest BLOB NOT NULL, issued_at INTEGER NOT NULL, idle_expires_at INTEGER NOT NULL, absolute_expires_at INTEGER NOT NULL, last_step_up_at INTEGER, strength TEXT NOT NULL, revoked_at INTEGER)")
        try await initial.connection.query("CREATE TABLE authentication_factors (factor_id TEXT PRIMARY KEY, account_did TEXT NOT NULL, kind TEXT NOT NULL, label TEXT NOT NULL, lookup_digest BLOB NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER, disabled_at INTEGER)")
        try await initial.connection.query("CREATE TABLE factor_challenges (challenge_digest BLOB PRIMARY KEY, account_did TEXT NOT NULL, factor_id TEXT, purpose TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER)")
        try await initial.connection.query("CREATE TABLE totp_secret_envelopes (factor_id TEXT PRIMARY KEY, account_did TEXT NOT NULL, key_reference TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, authentication_tag BLOB NOT NULL)")
        try await initial.connection.query("CREATE TABLE recovery_code_digests (account_did TEXT NOT NULL, digest BLOB NOT NULL, issued_at INTEGER NOT NULL, consumed_at INTEGER, PRIMARY KEY(account_did, digest))")
        try await initial.connection.query("CREATE TABLE webauthn_credentials (credential_id_digest BLOB PRIMARY KEY, account_did TEXT NOT NULL, factor_id TEXT NOT NULL, public_key_reference TEXT NOT NULL, sign_count INTEGER NOT NULL, transports BLOB NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER, disabled_at INTEGER)")
        try await initial.connection.query("CREATE TABLE webauthn_challenges (challenge_digest BLOB PRIMARY KEY, account_did TEXT NOT NULL, credential_id_digest BLOB, relying_party_id TEXT NOT NULL, origin TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER)")
        try await initial.connection.query("INSERT INTO identity_bindings(account_did, identity_did, method, handle, state) VALUES ('\(accountA)', '\(accountA)', 'plc', 'alice.example', 'active')")
        try await initial.connection.query("INSERT INTO did_web_claim_transactions(request_id, account_did, target_did, handle, claim_nonce_digest, state, expires_at) VALUES ('claim-old', '\(accountA)', 'did:web:example.com', 'alice.example', zeroblob(32), 'reserved', 100)")
        try await initial.connection.query("INSERT INTO app_passwords(app_password_id, account_did, canonical_name, scope_strings, secret_digest, created_at) VALUES ('app-old', '\(accountA)', 'primary', x'00', zeroblob(32), 1)")
        try await initial.connection.query("INSERT INTO legacy_session_families(family_id, account_did, app_password_id, created_at, expires_at) VALUES ('family-old', '\(accountA)', 'app-old', 1, 100)")
        try await initial.connection.query("INSERT INTO legacy_sessions(session_digest, family_id, account_did, app_password_id, scope_strings, issued_at, expires_at) VALUES (zeroblob(32), 'family-old', '\(accountA)', 'app-old', x'00', 1, 100)")
        try await initial.connection.query("DELETE FROM control_schema_migrations WHERE version = 7")
        try await initial.close()

        let upgraded = try await SQLiteControlDatabase(dataDirectory: root)
        let markers = try await upgraded.connection.query("SELECT version FROM control_schema_migrations ORDER BY version")
        XCTAssertEqual(markers.compactMap { $0.column("version")?.integer }, [1, 2, 3, 4, 5, 6, 7])
        for (table, column) in [("did_web_claim_transactions", "reserved_key_id"), ("did_web_claim_transactions", "claim_receipt_digest"), ("legacy_session_families", "reuse_detected_at"), ("legacy_sessions", "rotated_at"), ("legacy_sessions", "replaced_by_digest"), ("legacy_sessions", "previous_session_digest"), ("legacy_sessions", "reuse_detected_at")] {
            let columns = try await upgraded.connection.query("PRAGMA table_info(\(table))")
            XCTAssertTrue(columns.contains { $0.column("name")?.string == column }, "\(table).\(column)")
        }
        let claimRows = try await upgraded.connection.query("SELECT COUNT(*) AS count FROM did_web_claim_transactions WHERE request_id = 'claim-old'")
        let sessionRows = try await upgraded.connection.query("SELECT COUNT(*) AS count FROM legacy_sessions WHERE family_id = 'family-old'")
        XCTAssertEqual(claimRows.first?.column("count")?.integer, 1)
        XCTAssertEqual(sessionRows.first?.column("count")?.integer, 1)
        do {
            try await upgraded.connection.query("INSERT INTO legacy_session_families(family_id, account_did, app_password_id, created_at, expires_at) VALUES ('family-cross', '\(accountB)', 'app-old', 1, 100)")
            XCTFail("v7 must enforce family/app-password account ownership")
        } catch { }
        do {
            try await upgraded.connection.query("UPDATE did_web_claim_transactions SET account_did = NULL WHERE request_id = 'claim-old'")
            XCTFail("v7 must reject clearing nullable claim ownership")
        } catch { }
        do {
            try await upgraded.connection.query("UPDATE did_web_claim_transactions SET account_did = '\(accountB)' WHERE request_id = 'claim-old'")
            XCTFail("v7 must reject changing claim ownership")
        } catch { }
        try await upgraded.close()
    }

    func testHardeningMigrationFailureRollsBackMarkerAndPreservesInvalidLegacyData() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("swan-account-foundation-v7-rollback-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        try await database.connection.query("PRAGMA foreign_keys = OFF")
        try await database.connection.query("DROP TABLE legacy_session_families")
        try await database.connection.query("""
            CREATE TABLE legacy_session_families (
                family_id TEXT PRIMARY KEY, account_did TEXT NOT NULL, app_password_id TEXT,
                created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER,
                reuse_detected_at INTEGER
            )
            """)
        try await database.connection.query("INSERT INTO legacy_session_families(family_id, account_did, created_at, expires_at, reuse_detected_at) VALUES ('invalid-family', '\(accountA)', 1, 100, 5)")
        try await database.connection.query("DELETE FROM control_schema_migrations WHERE version = 7")
        do {
            _ = try await SQLiteControlDatabase(dataDirectory: root)
            XCTFail("invalid legacy lineage must abort v7 migration")
        } catch { }
        let marker = try await database.connection.query("SELECT version FROM control_schema_migrations WHERE version = 7")
        let row = try await database.connection.query("SELECT reuse_detected_at FROM legacy_session_families WHERE family_id = 'invalid-family'")
        XCTAssertTrue(marker.isEmpty)
        XCTAssertEqual(row.first?.column("reuse_detected_at")?.integer, 5)
        try await database.close()
    }
}
