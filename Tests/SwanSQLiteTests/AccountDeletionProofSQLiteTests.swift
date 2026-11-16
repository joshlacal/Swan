import Foundation
import SQLiteNIO
@testable import SwanSQLite
import SwanCore
import SwanStorage
import XCTest

/// The emailed half of `com.atproto.server.deleteAccount`: the proof shares
/// the durable email outbox with confirmation and recovery, and is consumable
/// exactly once, only for its own account, and only before it expires.
final class AccountDeletionProofSQLiteTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let otherDID = "did:plc:bcdefghijklmnopqrstuvwxy"
    private let email = try! AccountEmailAddress("person@example.com")
    private let otherEmail = try! AccountEmailAddress("other@example.com")
    private let verifier =
        "$argon2id$v=19$m=65536,t=2,p=1$initialsalt$initial-precomputed-verifier"
    private let now = Date(timeIntervalSince1970: 1_750_000_001)

    func testDeletionProofIsDeliveredAndConsumedExactlyOnce() async throws {
        let (root, database) = try await openDatabase()
        addTeardownBlock { try? await database.close(); try? FileManager.default.removeItem(at: root) }
        try await seedAccount(database, did: did, handle: "deleter.example.com", email: email)
        try await seedAccount(database, did: otherDID, handle: "bystander.example.com", email: otherEmail)

        let request = try deliveryRequest(did: did, email: email, deliveryByte: 0x11, proofByte: 0x21)
        let enqueued = try await database.enqueueEmailProofDelivery(request)
        XCTAssertEqual(enqueued, .enqueued)

        let lease = try await database.claimNextEmailDelivery(
            workerID: "worker-a", now: now, leaseDuration: 30
        )
        XCTAssertEqual(lease?.purpose, .accountDeletion)
        XCTAssertEqual(lease?.did, did)
        XCTAssertEqual(lease?.email, email)

        let wrongDigest = try await database.consumeAccountDeletionProof(
            did: did, proofDigest: Data(repeating: 0x99, count: 32), now: now
        )
        XCTAssertEqual(wrongDigest, .invalidToken)
        let wrongAccount = try await database.consumeAccountDeletionProof(
            did: otherDID, proofDigest: request.proofDigest, now: now
        )
        XCTAssertEqual(wrongAccount, .invalidToken)

        let first = try await database.consumeAccountDeletionProof(
            did: did, proofDigest: request.proofDigest, now: now.addingTimeInterval(1)
        )
        XCTAssertEqual(first, .consumed)
        let second = try await database.consumeAccountDeletionProof(
            did: did, proofDigest: request.proofDigest, now: now.addingTimeInterval(2)
        )
        XCTAssertEqual(second, .invalidToken)

        let account = try await database.account(did: did)
        XCTAssertEqual(account?.status, .active)
        let credential = try await database.credential(did: did)
        XCTAssertNotNil(credential)
    }

    func testExpiredDeletionProofReportsExpiredWithoutConsuming() async throws {
        let (root, database) = try await openDatabase()
        addTeardownBlock { try? await database.close(); try? FileManager.default.removeItem(at: root) }
        try await seedAccount(database, did: did, handle: "deleter.example.com", email: email)
        let request = try deliveryRequest(
            did: did, email: email, deliveryByte: 0x12, proofByte: 0x22, lifetime: 900
        )
        _ = try await database.enqueueEmailProofDelivery(request)

        let expired = try await database.consumeAccountDeletionProof(
            did: did, proofDigest: request.proofDigest, now: now.addingTimeInterval(901)
        )
        XCTAssertEqual(expired, .expiredToken)
        let account = try await database.account(did: did)
        XCTAssertEqual(account?.status, .active)
        let rows = try await database.connection.query(
            "SELECT consumed_at FROM account_email_tokens WHERE did = ? AND purpose = 'delete-account'",
            [.text(did)]
        )
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows.first?.column("consumed_at"), .null)
    }

    func testDeletionAndConfirmationProofsCannotStandInForEachOther() async throws {
        let (root, database) = try await openDatabase()
        addTeardownBlock { try? await database.close(); try? FileManager.default.removeItem(at: root) }
        try await seedAccount(database, did: did, handle: "deleter.example.com", email: email)

        let confirmation = try deliveryRequest(
            did: did, email: email, purpose: .verifyEmail, deliveryByte: 0x13, proofByte: 0x23
        )
        _ = try await database.enqueueEmailProofDelivery(confirmation)
        let deletion = try deliveryRequest(did: did, email: email, deliveryByte: 0x14, proofByte: 0x24)
        _ = try await database.enqueueEmailProofDelivery(deletion)

        let confirmationAsDeletion = try await database.consumeAccountDeletionProof(
            did: did, proofDigest: confirmation.proofDigest, now: now
        )
        XCTAssertEqual(confirmationAsDeletion, .invalidToken)
        let deletionAsConfirmation = try await database.confirmEmailProof(
            try AccountEmailConfirmationRequest(did: did, email: email, proofDigest: deletion.proofDigest),
            now: now
        )
        XCTAssertEqual(deletionAsConfirmation, .invalidToken)

        // A newer deletion request replaces the outstanding deletion proof only.
        let replacement = try deliveryRequest(did: did, email: email, deliveryByte: 0x15, proofByte: 0x25)
        _ = try await database.enqueueEmailProofDelivery(replacement)
        let replaced = try await database.consumeAccountDeletionProof(
            did: did, proofDigest: deletion.proofDigest, now: now
        )
        XCTAssertEqual(replaced, .invalidToken)
        let confirmed = try await database.confirmEmailProof(
            try AccountEmailConfirmationRequest(did: did, email: email, proofDigest: confirmation.proofDigest),
            now: now
        )
        XCTAssertEqual(confirmed, .confirmed)
    }

    func testDeletionProofIsRefusedOnceTheAccountIsNotActive() async throws {
        let (root, database) = try await openDatabase()
        addTeardownBlock { try? await database.close(); try? FileManager.default.removeItem(at: root) }
        try await seedAccount(database, did: did, handle: "deleter.example.com", email: email)
        let request = try deliveryRequest(did: did, email: email, deliveryByte: 0x16, proofByte: 0x26)
        _ = try await database.enqueueEmailProofDelivery(request)
        _ = try await database.transitionStatus(
            did: did, to: .deactivated, declaration: AccountLifecycleDeclaration(),
            now: now.addingTimeInterval(1)
        )

        let outcome = try await database.consumeAccountDeletionProof(
            did: did, proofDigest: request.proofDigest, now: now.addingTimeInterval(2)
        )
        XCTAssertEqual(outcome, .invalidToken)
    }

    func testExistingEmailTablesAcceptDeletionProofsAfterReopen() async throws {
        let (root, database) = try await openDatabase()
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        try await seedAccount(database, did: did, handle: "deleter.example.com", email: email)
        let confirmation = try deliveryRequest(
            did: did, email: email, purpose: .verifyEmail, deliveryByte: 0x17, proofByte: 0x27
        )
        _ = try await database.enqueueEmailProofDelivery(confirmation)
        try await database.close()

        // Recreate both tables with the purpose constraint every database
        // created before this change carries, keeping the outstanding row.
        let path = SQLiteLayout.controlDatabase(in: root).path
        let previous = try await SQLiteConnection.open(storage: .file(path: path))
        for statement in Self.previousEmailTableStatements {
            _ = try await previous.query(statement)
        }
        let previousSchema = try await previous.query(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'account_email_tokens'"
        )
        XCTAssertFalse(previousSchema.first?.column("sql")?.string?.contains("delete-account") ?? true)
        try await previous.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        addTeardownBlock { try? await reopened.close() }
        let retained = try await reopened.connection.query(
            "SELECT purpose FROM account_email_tokens WHERE did = ?", [.text(did)]
        )
        XCTAssertEqual(retained.map { $0.column("purpose")?.string }, ["verify-email"])
        let retainedOutbox = try await reopened.connection.query(
            "SELECT purpose, send_started_at FROM account_email_delivery_outbox WHERE did = ?",
            [.text(did)]
        )
        XCTAssertEqual(retainedOutbox.map { $0.column("purpose")?.string }, ["verify-email"])

        let deletion = try deliveryRequest(did: did, email: email, deliveryByte: 0x18, proofByte: 0x28)
        let enqueued = try await reopened.enqueueEmailProofDelivery(deletion)
        XCTAssertEqual(enqueued, .enqueued)
        let consumed = try await reopened.consumeAccountDeletionProof(
            did: did, proofDigest: deletion.proofDigest, now: now
        )
        XCTAssertEqual(consumed, .consumed)
        let confirmed = try await reopened.confirmEmailProof(
            try AccountEmailConfirmationRequest(did: did, email: email, proofDigest: confirmation.proofDigest),
            now: now
        )
        XCTAssertEqual(confirmed, .confirmed)
        // Constraint triggers survive the rebuild.
        let triggers = try await reopened.connection.query(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'trigger' AND tbl_name = 'account_email_tokens'
            ORDER BY name
            """
        )
        XCTAssertEqual(
            triggers.compactMap { $0.column("name")?.string },
            [
                "account_email_tokens_email_required_insert",
                "account_email_tokens_email_required_update",
            ]
        )
        do {
            _ = try await reopened.connection.query(
                """
                INSERT INTO account_email_tokens(digest, did, email, purpose, expires_at)
                VALUES (?, ?, NULL, 'delete-account', 1)
                """,
                [Data(repeating: 0x31, count: 32).sqliteData!, .text(did)]
            )
            XCTFail("an address-less email proof must be refused")
        } catch {}
    }

    func testRebuildLeavesReferencesFromOtherTablesOnTheCanonicalName() async throws {
        let (root, database) = try await openDatabase()
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        try await seedAccount(database, did: did, handle: "deleter.example.com", email: email)
        try await database.close()

        let path = SQLiteLayout.controlDatabase(in: root).path
        let previous = try await SQLiteConnection.open(storage: .file(path: path))
        for statement in Self.previousEmailTableStatements {
            _ = try await previous.query(statement)
        }
        for table in ["account_email_tokens", "account_email_delivery_outbox"] {
            _ = try await previous.query(
                "CREATE TABLE \(table)_reference_probe(parent TEXT REFERENCES \(table))"
            )
        }
        try await previous.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        addTeardownBlock { try? await reopened.close() }
        for table in ["account_email_tokens", "account_email_delivery_outbox"] {
            let probe = try await reopened.connection.query(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
                [.text("\(table)_reference_probe")]
            )
            let sql = try XCTUnwrap(probe.first?.column("sql")?.string)
            XCTAssertTrue(sql.contains("REFERENCES \(table))"), sql)
            XCTAssertFalse(sql.contains("_purpose_v1"), sql)
        }
    }

    // MARK: - Helpers

    /// The pre-change shapes of both tables, as `addColumnIfMissing` left
    /// them on an upgraded database (late columns appended at the end).
    private static let previousEmailTableStatements: [String] = [
        "ALTER TABLE account_email_tokens RENAME TO account_email_tokens_saved",
        """
        CREATE TABLE account_email_tokens (
            digest BLOB PRIMARY KEY CHECK(length(digest) = 32),
            did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
            email TEXT NOT NULL,
            purpose TEXT NOT NULL CHECK(purpose IN ('verify-email', 'password-recovery')),
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
            consumed_at INTEGER CHECK(consumed_at >= 0),
            delivery_id TEXT
        )
        """,
        """
        INSERT INTO account_email_tokens(digest, did, email, purpose, expires_at, consumed_at, delivery_id)
        SELECT digest, did, email, purpose, expires_at, consumed_at, delivery_id
        FROM account_email_tokens_saved
        """,
        "DROP TABLE account_email_tokens_saved",
        "ALTER TABLE account_email_delivery_outbox RENAME TO account_email_delivery_outbox_saved",
        """
        CREATE TABLE account_email_delivery_outbox (
            delivery_id TEXT PRIMARY KEY
                CHECK(length(delivery_id) = 43)
                CHECK(delivery_id NOT GLOB '*[^A-Za-z0-9_-]*'),
            did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
            email TEXT NOT NULL,
            email_generation INTEGER NOT NULL CHECK(email_generation > 0),
            purpose TEXT NOT NULL
                CHECK(purpose IN ('verify-email', 'password-recovery')),
            expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
            state TEXT NOT NULL
                CHECK(state IN ('pending', 'leased', 'sent', 'cancelled')),
            lease_owner TEXT,
            lease_expires_at INTEGER CHECK(lease_expires_at >= 0),
            attempts INTEGER NOT NULL DEFAULT 0
                CHECK(attempts BETWEEN 0 AND 64),
            next_attempt_at INTEGER NOT NULL CHECK(next_attempt_at >= 0),
            created_at INTEGER NOT NULL CHECK(created_at >= 0),
            sent_at INTEGER CHECK(sent_at >= 0),
            send_started_at INTEGER,
            CHECK(
                (state = 'leased' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
                OR
                (state != 'leased' AND lease_owner IS NULL AND lease_expires_at IS NULL)
            )
        )
        """,
        """
        INSERT INTO account_email_delivery_outbox(
            delivery_id, did, email, email_generation, purpose, expires_at, state,
            lease_owner, lease_expires_at, attempts, next_attempt_at, created_at,
            sent_at, send_started_at
        )
        SELECT delivery_id, did, email, email_generation, purpose, expires_at, state,
               lease_owner, lease_expires_at, attempts, next_attempt_at, created_at,
               sent_at, send_started_at
        FROM account_email_delivery_outbox_saved
        """,
        "DROP TABLE account_email_delivery_outbox_saved",
    ]

    private func openDatabase() async throws -> (URL, SQLiteControlDatabase) {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanAccountDeletionProof-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return (root, try await SQLiteControlDatabase(dataDirectory: root))
    }

    private func seedAccount(
        _ database: SQLiteControlDatabase,
        did: String,
        handle: String,
        email: AccountEmailAddress
    ) async throws {
        _ = try await database.createAccount(
            try AccountControlRegistration(
                did: did,
                canonicalHandle: handle,
                passwordVerifier: verifier,
                signingKey: try .init(purpose: .signing, generation: 1),
                rotationKey: try .init(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )
        try await database.associateEmail(did: did, email: email, now: Date(timeIntervalSince1970: 1_750_000_000.5))
    }

    private func deliveryRequest(
        did: String,
        email: AccountEmailAddress,
        purpose: AccountEmailTokenPurpose = .accountDeletion,
        deliveryByte: UInt8,
        proofByte: UInt8,
        lifetime: TimeInterval = 900
    ) throws -> AccountEmailProofDeliveryRequest {
        try AccountEmailProofDeliveryRequest(
            deliveryID: AccountEmailDeliveryID(
                rawValue: Data(repeating: deliveryByte, count: 32).base64EncodedString()
                    .replacingOccurrences(of: "+", with: "-")
                    .replacingOccurrences(of: "/", with: "_")
                    .replacingOccurrences(of: "=", with: "")
            ),
            did: did,
            email: email,
            purpose: purpose,
            proofDigest: Data(repeating: proofByte, count: 32),
            expiresAt: now.addingTimeInterval(lifetime),
            now: now
        )
    }
}
