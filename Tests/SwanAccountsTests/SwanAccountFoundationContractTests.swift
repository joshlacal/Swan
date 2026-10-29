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
        XCTAssertThrowsError(try decoder.decode(LegacySessionFamilyMetadata.self, from: Data(#"{"familyID":"f","accountDID":"did:plc:a","createdAt":1,"expiresAt":10,"revokedAt":4,"reuseDetectedAt":6}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(LegacySessionMetadata.self, from: Data(#"{"sessionID":"legacy-1","familyID":"f","accountDID":"did:plc:a","scopeStrings":[],"issuedAt":1,"expiresAt":2,"replacedByDigest":"AQI="}"#.utf8)))
        XCTAssertThrowsError(try decoder.decode(LegacySessionMetadata.self, from: Data(#"{"sessionID":"legacy-1","familyID":"f","accountDID":"did:plc:a","scopeStrings":[],"issuedAt":1,"expiresAt":10,"revokedAt":4,"reuseDetectedAt":6}"#.utf8)))
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
            permissions: SwanScopePermissions(
                rawScopes: ["atproto"],
                subject: "did:plc:aaaaaaaaaaaaaaaaaaaaaa"
            )
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
        let outcome = try LegacySessionRotationOutcome.reuseDetectedAndFamilyRevoked(
                familyID: family.familyID, detectedAt: detectedAt, revokedAt: revokedAt
        )
        XCTAssertEqual(outcome.kind, .reuseDetectedAndFamilyRevoked)
        XCTAssertEqual(outcome.familyID, Optional(family.familyID))
        XCTAssertEqual(outcome.detectedAt, Optional(detectedAt))
        XCTAssertEqual(outcome.revokedAt, Optional(revokedAt))
        XCTAssertThrowsError(try LegacySessionFamilyMetadata(
            familyID: family.familyID, accountDID: accountA, appPasswordID: nil,
            createdAt: Date(timeIntervalSince1970: 1), expiresAt: Date(timeIntervalSince1970: 10),
            reuseDetectedAt: detectedAt
        ))
        XCTAssertThrowsError(try LegacySessionFamilyMetadata(
            familyID: family.familyID, accountDID: accountA, appPasswordID: nil,
            createdAt: Date(timeIntervalSince1970: 1), expiresAt: Date(timeIntervalSince1970: 10),
            revokedAt: Date(timeIntervalSince1970: 4), reuseDetectedAt: detectedAt
        ))
        XCTAssertThrowsError(try LegacySessionMetadata(
            sessionID: try LegacySessionID(rawValue: "legacy-reuse"), familyID: family.familyID,
            accountDID: accountA, appPasswordID: nil, scopeStrings: [],
            issuedAt: Date(timeIntervalSince1970: 1), expiresAt: Date(timeIntervalSince1970: 10),
            revokedAt: Date(timeIntervalSince1970: 4), reuseDetectedAt: detectedAt
        ))
        XCTAssertThrowsError(try LegacySessionRotationOutcome.reuseDetectedAndFamilyRevoked(
            familyID: family.familyID, detectedAt: detectedAt, revokedAt: Date(timeIntervalSince1970: 4)
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
        XCTAssertEqual(ControlSchemaMigrationVersion.accountProgramIntegration.rawValue, 8)
        XCTAssertEqual(ControlSchemaMigrationVersion.spaceCredentialRevocations.rawValue, 9)
        XCTAssertEqual(ControlSchemaMigrationVersion.accountKEMBackfill.rawValue, 10)
        // The registry names every marker the database records, contiguously.
        XCTAssertEqual(ControlSchemaMigrationVersion.allCases.map(\.rawValue), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        // Every unconditional statement must be idempotent and additive.
        // Rewrites belong in a marker-gated migration (v7-v9), never here.
        let additivePrefixes = [
            "CREATE TABLE IF NOT EXISTS ", "CREATE INDEX IF NOT EXISTS ",
            "CREATE TRIGGER IF NOT EXISTS ", "INSERT OR IGNORE INTO control_schema_migrations(",
        ]
        for statement in SQLiteLayout.controlMigrations.dropFirst(SQLiteLayout.controlConnectionPragmas.count) {
            let sql = statement.split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.hasPrefix("--") }
                .joined(separator: " ")
            XCTAssertTrue(additivePrefixes.contains { sql.hasPrefix($0) }, String(sql.prefix(80)))
        }
        let schema = SQLiteLayout.controlMigrations.joined(separator: "\n")
        for table in [
            "control_schema_migrations", "identity_bindings", "did_web_claim_transactions",
            "signup_authorizations", "signup_invites", "legacy_session_families",
            "management_sessions", "authentication_factors", "factor_challenges",
            "totp_secret_envelopes", "recovery_code_digests", "webauthn_credentials", "webauthn_challenges",
            "account_kem_backfill"
        ] {
            XCTAssertTrue(schema.contains("CREATE TABLE IF NOT EXISTS \(table)"), table)
        }
        // v10 is bounded by the account registry: one row per account, removed
        // with the account, and only the three backfill outcomes.
        let kemBackfill = try XCTUnwrap(SQLiteLayout.controlMigrations.first {
            $0.contains("CREATE TABLE IF NOT EXISTS account_kem_backfill")
        })
        XCTAssertTrue(kemBackfill.contains("account_did TEXT PRIMARY KEY REFERENCES accounts(did) ON DELETE CASCADE"))
        XCTAssertTrue(kemBackfill.contains("CHECK(status IN ('pending', 'published', 'manual'))"))
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
        XCTAssertEqual(markerRows.compactMap { $0.column("version")?.integer }, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        let tables = try await database.connection.query(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('identity_bindings', 'signup_authorizations', 'legacy_session_tokens', 'management_sessions', 'authentication_factors', 'factor_challenges', 'totp_secret_envelopes', 'recovery_code_digests', 'webauthn_credentials', 'webauthn_challenges')"
        )
        XCTAssertEqual(tables.count, 10)
        let obsoleteTables = try await database.connection.query(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('app_passwords', 'legacy_sessions')"
        )
        XCTAssertTrue(obsoleteTables.isEmpty)
        let foreignKeys = try await database.connection.query("PRAGMA foreign_keys")
        XCTAssertEqual(foreignKeys.first?.column("foreign_keys")?.integer, 1)

        try await database.connection.query("INSERT INTO accounts(did, handle, status, created_at) VALUES ('\(accountA)', 'alice.example', 'active', 1), ('\(accountB)', 'bob.example', 'active', 1)")
        try await database.connection.query("INSERT INTO identity_bindings(account_did, identity_did, method, handle, state) VALUES ('\(accountA)', '\(accountA)', 'plc', 'alice.example', 'active')")
        do {
            try await database.connection.query("INSERT INTO identity_bindings(account_did, identity_did, method, handle, document_digest, claim_receipt_digest, reserved_key_id, state) VALUES ('\(accountB)', 'did:web:empty-key.example', 'did-web', 'empty.example', zeroblob(32), zeroblob(32), '', 'active')")
            XCTFail("did:web reserved key ID must not be empty")
        } catch { }
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
        try await database.connection.query("INSERT INTO account_app_passwords(id, did, name, digest, scopes, created_at) VALUES ('app-a', '\(accountA)', 'primary', randomblob(32), 'atproto', 1)")
        do {
            try await database.connection.query("INSERT INTO legacy_session_families(family_id, did, app_password_id, created_at) VALUES ('family-b', '\(accountB)', 'app-a', 1)")
            XCTFail("legacy family must match app-password account")
        } catch { }
        try await database.connection.query("INSERT INTO legacy_session_families(family_id, did, app_password_id, created_at) VALUES ('family-a', '\(accountA)', 'app-a', 1)")
        do {
            try await database.connection.query("INSERT INTO legacy_session_families(family_id, did, app_password_id, created_at, revoked_at, reuse_detected_at) VALUES ('family-order', '\(accountA)', 'app-a', 1, 5, 6)")
            XCTFail("legacy family revocation cannot precede reuse detection")
        } catch { }
        try await database.connection.query("INSERT INTO legacy_session_tokens(digest, family_id, kind, expires_at) VALUES (randomblob(32), 'family-a', 'access', 100)")
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
        try await database.connection.query("INSERT INTO account_kem_backfill(account_did, status) VALUES ('\(accountA)', 'pending'), ('\(accountB)', 'pending')")
        do {
            try await database.connection.query("INSERT INTO account_kem_backfill(account_did, status) VALUES ('\(accountA)', 'pending')")
            XCTFail("KEM backfill must hold at most one row per account")
        } catch { }
        do {
            try await database.connection.query("INSERT INTO account_kem_backfill(account_did, status) VALUES ('did:plc:zzzzzzzzzzzzzzzzzzzzzz', 'pending')")
            XCTFail("KEM backfill rows must belong to a registered account")
        } catch { }
        do {
            try await database.connection.query("UPDATE account_kem_backfill SET status = 'abandoned' WHERE account_did = '\(accountB)'")
            XCTFail("KEM backfill status must be pending, published or manual")
        } catch { }
        try await database.connection.query("DELETE FROM accounts WHERE did = '\(accountA)'")
        let cascaded = try await database.connection.query("SELECT (SELECT COUNT(*) FROM identity_bindings WHERE account_did = '\(accountA)') AS bindings, (SELECT COUNT(*) FROM authentication_factors WHERE account_did = '\(accountA)') AS factors, (SELECT COUNT(*) FROM account_kem_backfill WHERE account_did = '\(accountA)') AS kem_backfill, (SELECT COUNT(*) FROM account_kem_backfill WHERE account_did = '\(accountB)') AS retained_kem_backfill")
        XCTAssertEqual(cascaded.first?.column("bindings")?.integer, 0)
        XCTAssertEqual(cascaded.first?.column("factors")?.integer, 0)
        XCTAssertEqual(cascaded.first?.column("kem_backfill")?.integer, 0)
        XCTAssertEqual(cascaded.first?.column("retained_kem_backfill")?.integer, 1)
        try await database.connection.query("BEGIN IMMEDIATE")
        try await database.connection.query("INSERT INTO control_schema_migrations(version, applied_at) VALUES (99, 1)")
        try await database.connection.query("ROLLBACK")
        let rolledBackMarkers = try await database.connection.query("SELECT version FROM control_schema_migrations WHERE version = 99")
        XCTAssertTrue(rolledBackMarkers.isEmpty)
        try await database.close()
        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        let reopenedMarkers = try await reopened.connection.query("SELECT version FROM control_schema_migrations ORDER BY version")
        XCTAssertEqual(reopenedMarkers.compactMap { $0.column("version")?.integer }, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        try await reopened.close()
    }

    /// v9 (atproto#5567) is additive: a database last migrated at v8 (so
    /// also without v10) gains the revocation table, the KEM backfill table
    /// and both markers on its next open, keeping its data.
    func testSpaceCredentialRevocationsV9UpgradesAV8Database() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("swan-space-revocations-v9-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        try await database.connection.query(
            "INSERT INTO accounts(did,handle,status,created_at) VALUES ('did:plc:aaaaaaaaaaaaaaaaaaaaaaaa','v8.example','active',1)"
        )
        // Rewind to the v8 shape, which predates both v9 and v10.
        try await database.connection.query("DROP TABLE permissioned_space_credential_revocations")
        try await database.connection.query("DROP TABLE account_kem_backfill")
        try await database.connection.query("DELETE FROM control_schema_migrations WHERE version IN (9, 10)")
        let rewound = try await database.connection.query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('permissioned_space_credential_revocations', 'account_kem_backfill')"
        )
        XCTAssertTrue(rewound.isEmpty, "positive control: the v8 shape has no revocation or KEM backfill table")
        let rewoundMarkers = try await database.connection.query(
            "SELECT version FROM control_schema_migrations ORDER BY version"
        )
        XCTAssertEqual(rewoundMarkers.compactMap { $0.column("version")?.integer }, [1, 2, 3, 4, 5, 6, 7, 8])
        try await database.close()

        let upgraded = try await SQLiteControlDatabase(dataDirectory: root)
        let markers = try await upgraded.connection.query(
            "SELECT version FROM control_schema_migrations ORDER BY version"
        )
        XCTAssertEqual(markers.compactMap { $0.column("version")?.integer }, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        let tables = try await upgraded.connection.query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('permissioned_space_credential_revocations', 'account_kem_backfill')"
        )
        XCTAssertEqual(tables.count, 2)
        let accounts = try await upgraded.connection.query("SELECT did FROM accounts")
        XCTAssertEqual(accounts.compactMap { $0.column("did")?.string }, ["did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"])
        try await upgraded.recordSpaceCredentialRevocations(
            digests: [Data(repeating: 7, count: 32)],
            retainUntil: Date(timeIntervalSince1970: 2_000_000_000),
            now: Date(timeIntervalSince1970: 1_750_000_000)
        )
        let revoked = try await upgraded.isSpaceCredentialRevoked(
            digest: Data(repeating: 7, count: 32),
            now: Date(timeIntervalSince1970: 1_750_000_000)
        )
        XCTAssertTrue(revoked)
        try await upgraded.close()
    }

    /// v10 (October 22 `#atproto_kem` backfill) is additive: a database last
    /// migrated at v9 keeps every row, gains an empty backfill table and the
    /// marker, and then enrolls only the accounts that already existed.
    func testAccountKEMBackfillV10UpgradesAV9DatabaseAndEnrollsExistingAccounts() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("swan-account-kem-backfill-v10-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let first = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
        let second = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"
        let revokedDigest = Data(repeating: 9, count: 32)
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        try await database.connection.query(
            "INSERT INTO accounts(did,handle,status,created_at) VALUES ('\(first)','first.example','active',1),('\(second)','second.example','active',1)"
        )
        try await database.connection.query(
            "INSERT INTO identity_bindings(account_did,identity_did,method,handle,state) VALUES ('\(first)','\(first)','plc','first.example','active')"
        )
        try await database.recordSpaceCredentialRevocations(
            digests: [revokedDigest],
            retainUntil: Date(timeIntervalSince1970: 2_000_000_000),
            now: now
        )
        // Rewind to the v9 shape.
        try await database.connection.query("DROP TABLE account_kem_backfill")
        try await database.connection.query("DELETE FROM control_schema_migrations WHERE version = 10")
        let rewound = try await database.connection.query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='account_kem_backfill'"
        )
        XCTAssertTrue(rewound.isEmpty, "positive control: the v9 shape has no KEM backfill table")
        let rewoundMarkers = try await database.connection.query(
            "SELECT version FROM control_schema_migrations ORDER BY version"
        )
        XCTAssertEqual(rewoundMarkers.compactMap { $0.column("version")?.integer }, [1, 2, 3, 4, 5, 6, 7, 8, 9])
        try await database.close()

        let upgraded = try await SQLiteControlDatabase(dataDirectory: root)
        let markers = try await upgraded.connection.query(
            "SELECT version FROM control_schema_migrations ORDER BY version"
        )
        XCTAssertEqual(markers.compactMap { $0.column("version")?.integer }, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        let preserved = try await upgraded.connection.query(
            "SELECT (SELECT COUNT(*) FROM accounts) AS accounts, (SELECT COUNT(*) FROM identity_bindings WHERE account_did = '\(first)') AS bindings, (SELECT COUNT(*) FROM account_kem_backfill) AS kem_backfill"
        )
        XCTAssertEqual(preserved.first?.column("accounts")?.integer, 2)
        XCTAssertEqual(preserved.first?.column("bindings")?.integer, 1)
        XCTAssertEqual(preserved.first?.column("kem_backfill")?.integer, 0, "the upgrade itself writes no backfill rows")
        let stillRevoked = try await upgraded.isSpaceCredentialRevoked(digest: revokedDigest, now: now)
        XCTAssertTrue(stillRevoked)

        let claimValue = try await upgraded.claimAccountKEMBackfill(now: 100)
        let claim = try XCTUnwrap(claimValue, "accounts created before v10 must be backfilled")
        XCTAssertEqual(claim.did, first)
        XCTAssertFalse(claim.requiresManualPublication)
        let enrolled = try await upgraded.connection.query(
            "SELECT account_did FROM account_kem_backfill ORDER BY account_did"
        )
        XCTAssertEqual(enrolled.compactMap { $0.column("account_did")?.string }, [first, second])
        try await upgraded.close()

        // Reopening is a no-op for an already-applied v10.
        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        let reopenedMarkers = try await reopened.connection.query(
            "SELECT version FROM control_schema_migrations ORDER BY version"
        )
        XCTAssertEqual(reopenedMarkers.compactMap { $0.column("version")?.integer }, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        let lease = try await reopened.connection.query(
            "SELECT lease_token FROM account_kem_backfill WHERE account_did = '\(first)'"
        )
        XCTAssertEqual(lease.first?.column("lease_token")?.string, claim.token)
        try await reopened.close()
    }

    func testAccountProgramV8InstallsAuxiliaryTablesAndReleasedDidWebCanBeReclaimed() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("swan-account-program-v8-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let expected = [
            "did_web_signing_key_reservations", "did_web_step_up_receipts",
            "signup_invite_reservations", "signup_email_proofs",
            "signup_email_proof_reservations", "signup_authorization_reservations",
            "signup_authorization_results", "signup_email_request_outbox",
            "management_pre_auth", "totp_replay_state", "mfa_factor_tokens",
            "mfa_audit_events", "mfa_webauthn_challenge_context",
        ]
        let names = try await database.connection.query(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).compactMap { $0.column("name")?.string }
        XCTAssertTrue(Set(expected).isSubset(of: Set(names)))

        let first = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
        let second = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"
        let third = "did:plc:cccccccccccccccccccccccc"
        let fourth = "did:plc:dddddddddddddddddddddddd"
        try await database.connection.query(
            "INSERT INTO accounts(did,handle,status,created_at) VALUES ('\(first)','first.example','active',1),('\(second)','second.example','active',1),('\(third)','third.example','active',1),('\(fourth)','fourth.example','active',1)"
        )
        try await database.connection.query("PRAGMA foreign_keys = OFF")
        try await database.connection.query("DROP TABLE identity_bindings")
        try await database.connection.query(
            """
            CREATE TABLE identity_bindings (
              account_did TEXT PRIMARY KEY REFERENCES accounts(did) ON DELETE CASCADE,
              identity_did TEXT NOT NULL UNIQUE,
              method TEXT NOT NULL CHECK(method IN ('plc', 'did-web')),
              handle TEXT NOT NULL,
              document_digest BLOB CHECK(document_digest IS NULL OR length(document_digest) = 32),
              claim_receipt_digest BLOB CHECK(claim_receipt_digest IS NULL OR length(claim_receipt_digest) = 32),
              reserved_key_id TEXT, last_validated_at INTEGER, grace_expires_at INTEGER,
              state TEXT NOT NULL CHECK(state IN ('active', 'suspended', 'released'))
            )
            """
        )
        try await database.connection.query(
            "INSERT INTO identity_bindings(account_did,identity_did,method,handle,document_digest,claim_receipt_digest,reserved_key_id,state) VALUES ('\(first)','did:web:reusable.example','did-web','reusable.example',zeroblob(32),randomblob(32),'key-1','released')"
        )
        try await database.connection.query("DELETE FROM control_schema_migrations WHERE version = 8")
        try await database.connection.query("PRAGMA foreign_keys = ON")
        try await database.close()

        let migrated = try await SQLiteControlDatabase(dataDirectory: root)
        try await migrated.connection.query(
            "INSERT INTO identity_bindings(account_did,identity_did,method,handle,document_digest,claim_receipt_digest,reserved_key_id,state) VALUES ('\(second)','did:web:reusable.example','did-web','second.example',randomblob(32),randomblob(32),'key-2','active')"
        )
        do {
            try await migrated.connection.query(
                "INSERT INTO identity_bindings(account_did,identity_did,method,handle,document_digest,claim_receipt_digest,reserved_key_id,state) VALUES ('\(third)','did:web:reusable.example','did-web','third.example',randomblob(32),randomblob(32),'key-3','active')"
            )
            XCTFail("duplicate active did:web identity must be rejected")
        } catch { }
        do {
            try await migrated.connection.query(
                "INSERT INTO identity_bindings(account_did,identity_did,method,handle,document_digest,claim_receipt_digest,reserved_key_id,state) VALUES ('\(fourth)','did:web:fourth.example','did-web','second.example',randomblob(32),randomblob(32),'key-4','active')"
            )
            XCTFail("duplicate active did:web handle must be rejected")
        } catch { }
        try await migrated.close()
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
            "management_sessions", "legacy_session_tokens", "legacy_session_families",
            "account_app_passwords", "signup_invites", "signup_authorizations",
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
        try await initial.connection.query("CREATE TABLE account_app_passwords (id TEXT PRIMARY KEY, did TEXT NOT NULL, name TEXT NOT NULL, digest BLOB NOT NULL, scopes TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(did, name))")
        try await initial.connection.query("CREATE TABLE legacy_session_families (family_id TEXT PRIMARY KEY, did TEXT NOT NULL, app_password_id TEXT, created_at INTEGER NOT NULL, revoked_at INTEGER)")
        try await initial.connection.query("CREATE TABLE legacy_session_tokens (digest BLOB PRIMARY KEY, family_id TEXT NOT NULL, kind TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER)")
        try await initial.connection.query("CREATE TABLE management_sessions (session_digest BLOB PRIMARY KEY, account_did TEXT NOT NULL, csrf_digest BLOB NOT NULL, issued_at INTEGER NOT NULL, idle_expires_at INTEGER NOT NULL, absolute_expires_at INTEGER NOT NULL, last_step_up_at INTEGER, strength TEXT NOT NULL, revoked_at INTEGER)")
        try await initial.connection.query("CREATE TABLE authentication_factors (factor_id TEXT PRIMARY KEY, account_did TEXT NOT NULL, kind TEXT NOT NULL, label TEXT NOT NULL, lookup_digest BLOB NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER, disabled_at INTEGER)")
        try await initial.connection.query("CREATE TABLE factor_challenges (challenge_digest BLOB PRIMARY KEY, account_did TEXT NOT NULL, factor_id TEXT, purpose TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER)")
        try await initial.connection.query("CREATE TABLE totp_secret_envelopes (factor_id TEXT PRIMARY KEY, account_did TEXT NOT NULL, key_reference TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, authentication_tag BLOB NOT NULL)")
        try await initial.connection.query("CREATE TABLE recovery_code_digests (account_did TEXT NOT NULL, digest BLOB NOT NULL, issued_at INTEGER NOT NULL, consumed_at INTEGER, PRIMARY KEY(account_did, digest))")
        try await initial.connection.query("CREATE TABLE webauthn_credentials (credential_id_digest BLOB PRIMARY KEY, account_did TEXT NOT NULL, factor_id TEXT NOT NULL, public_key_reference TEXT NOT NULL, sign_count INTEGER NOT NULL, transports BLOB NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER, disabled_at INTEGER)")
        try await initial.connection.query("CREATE TABLE webauthn_challenges (challenge_digest BLOB PRIMARY KEY, account_did TEXT NOT NULL, credential_id_digest BLOB, relying_party_id TEXT NOT NULL, origin TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER)")
        try await initial.connection.query("INSERT INTO identity_bindings(account_did, identity_did, method, handle, state) VALUES ('\(accountA)', '\(accountA)', 'plc', 'alice.example', 'active')")
        try await initial.connection.query("INSERT INTO authentication_factors(factor_id, account_did, kind, label, lookup_digest, created_at) VALUES ('factor-old', '\(accountA)', 'passkey', 'old', zeroblob(32), 1)")
        try await initial.connection.query("INSERT INTO webauthn_credentials(credential_id_digest, account_did, factor_id, public_key_reference, sign_count, transports, created_at) VALUES (x'0303030303030303030303030303030303030303030303030303030303030303', '\(accountA)', 'factor-old', 'old-key', 1, x'00', 1)")
        try await initial.connection.query("INSERT INTO webauthn_challenges(challenge_digest, account_did, credential_id_digest, relying_party_id, origin, issued_at, expires_at) VALUES (x'0404040404040404040404040404040404040404040404040404040404040404', '\(accountA)', x'0303030303030303030303030303030303030303030303030303030303030303', 'example.com', 'https://example.com', 1, 100)")
        try await initial.connection.query("INSERT INTO did_web_claim_transactions(request_id, account_did, target_did, handle, claim_nonce_digest, state, expires_at) VALUES ('claim-old', '\(accountA)', 'did:web:example.com', 'alice.example', zeroblob(32), 'reserved', 100)")
        try await initial.connection.query("INSERT INTO account_app_passwords(id, did, name, digest, scopes, created_at) VALUES ('app-old', '\(accountA)', 'primary', zeroblob(32), 'repo:write', 1)")
        // A populated current-main database may already contain more than the
        // old account-program alpha ceiling. Preserve all 100 canonical rows
        // through the additive upgrade and reject only row 101.
        for index in 1 ..< 100 {
            try await initial.connection.query("INSERT INTO account_app_passwords(id, did, name, digest, scopes, created_at) VALUES ('app-old-\(index)', '\(accountA)', 'boundary-\(index)', zeroblob(32), 'atproto', \(index + 1))")
        }
        try await initial.connection.query("INSERT INTO legacy_session_families(family_id, did, app_password_id, created_at) VALUES ('family-old', '\(accountA)', 'app-old', 1)")
        try await initial.connection.query("INSERT INTO legacy_session_tokens(digest, family_id, kind, expires_at) VALUES (zeroblob(32), 'family-old', 'refresh', 100)")
        try await initial.connection.query("DELETE FROM control_schema_migrations WHERE version = 7")
        try await initial.close()

        let upgraded = try await SQLiteControlDatabase(dataDirectory: root)
        let markers = try await upgraded.connection.query("SELECT version FROM control_schema_migrations ORDER BY version")
        XCTAssertEqual(markers.compactMap { $0.column("version")?.integer }, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        for (table, column) in [("did_web_claim_transactions", "reserved_key_id"), ("did_web_claim_transactions", "claim_receipt_digest"), ("legacy_session_families", "reuse_detected_at")] {
            let columns = try await upgraded.connection.query("PRAGMA table_info(\(table))")
            XCTAssertTrue(columns.contains { $0.column("name")?.string == column }, "\(table).\(column)")
        }
        let claimRows = try await upgraded.connection.query("SELECT COUNT(*) AS count FROM did_web_claim_transactions WHERE request_id = 'claim-old'")
        let sessionRows = try await upgraded.connection.query("SELECT COUNT(*) AS count FROM legacy_session_tokens WHERE family_id = 'family-old'")
        let appPasswordRows = try await upgraded.connection.query("SELECT COUNT(*) AS count FROM account_app_passwords WHERE did = '\(accountA)'")
        XCTAssertEqual(claimRows.first?.column("count")?.integer, 1)
        XCTAssertEqual(sessionRows.first?.column("count")?.integer, 1)
        XCTAssertEqual(appPasswordRows.first?.column("count")?.integer, 100)
        do {
            try await upgraded.connection.query("INSERT INTO account_app_passwords(id, did, name, digest, scopes, created_at) VALUES ('app-overflow', '\(accountA)', 'overflow', zeroblob(32), 'atproto', 99)")
            XCTFail("the populated current-main fixture must retain the canonical account capacity")
        } catch { }
        do {
            try await upgraded.connection.query("UPDATE legacy_session_families SET revoked_at = 5, reuse_detected_at = 6 WHERE family_id = 'family-old'")
            XCTFail("v7 must reject family revocation before reuse detection")
        } catch { }
        do {
            try await upgraded.connection.query("INSERT INTO identity_bindings(account_did, identity_did, method, handle, document_digest, claim_receipt_digest, reserved_key_id, state) VALUES ('\(accountB)', 'did:web:empty-key.example', 'did-web', 'empty.example', zeroblob(32), zeroblob(32), '', 'active')")
            XCTFail("v7 must reject empty did:web reserved key IDs")
        } catch { }
        try await upgraded.connection.query("DELETE FROM webauthn_credentials WHERE credential_id_digest = x'0303030303030303030303030303030303030303030303030303030303030303'")
        let orphanedChallengeRows = try await upgraded.connection.query("SELECT COUNT(*) AS count FROM webauthn_challenges WHERE challenge_digest = x'0404040404040404040404040404040404040404040404040404040404040404'")
        XCTAssertEqual(orphanedChallengeRows.first?.column("count")?.integer, 0)
        do {
            try await upgraded.connection.query("INSERT INTO legacy_session_families(family_id, did, app_password_id, created_at) VALUES ('family-cross', '\(accountB)', 'app-old', 1)")
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
                family_id TEXT PRIMARY KEY, did TEXT NOT NULL, app_password_id TEXT,
                created_at INTEGER NOT NULL, revoked_at INTEGER,
                reuse_detected_at INTEGER
            )
            """)
        try await database.connection.query("INSERT INTO legacy_session_families(family_id, did, created_at, reuse_detected_at) VALUES ('invalid-family', '\(accountA)', 1, 5)")
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
