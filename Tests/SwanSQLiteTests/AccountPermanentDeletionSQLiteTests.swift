import Foundation
import SQLiteNIO
@testable import SwanSQLite
import SwanStorage
import XCTest

final class AccountPermanentDeletionSQLiteTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let otherDID = "did:plc:bcdefghijklmnopqrstuvwxy"
    private let verifier =
        "$argon2id$v=19$m=65536,t=2,p=1$initialsalt$initial-precomputed-verifier"
    private let genesisCID =
        "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    private let deletedDeliveryID = String(repeating: "D", count: 43)
    private let retainedDeliveryID = String(repeating: "R", count: 43)

    func testBeginDeletionAtomicallyScrubsAuthorityAndSurvivesReopen() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let createdAt = Date(timeIntervalSince1970: 1_750_000_100)
        _ = try await database.createAccount(
            try registration(
                did: did,
                handle: "delete-me.example.com",
                createdAt: createdAt
            )
        )
        _ = try await database.createAccount(
            try registration(
                did: otherDID,
                handle: "keep-me.example.com",
                createdAt: createdAt
            )
        )
        try await seedEmailAndOAuth(in: database, now: createdAt)
        let seededDeliveryRows = try await database.connection.query(
            """
            SELECT delivery_id, did
            FROM account_email_delivery_outbox
            ORDER BY did
            """
        )
        XCTAssertEqual(seededDeliveryRows.count, 2)
        XCTAssertEqual(
            Set(seededDeliveryRows.compactMap {
                $0.column("delivery_id")?.string
            }),
            Set([deletedDeliveryID, retainedDeliveryID])
        )
        _ = try await database.connection.query(
            """
            INSERT INTO plc_credential_key_continuity(issuer, terminal_cid)
            VALUES (?, ?), (?, ?)
            """,
            [
                .text(did), .text(genesisCID),
                .text(otherDID), .text(genesisCID),
            ]
        )
        let staging = try PLCAccountPreparationIntent(
            requestID: "delete-account-request",
            did: did,
            canonicalHandle: "delete-me.example.com",
            pdsOrigin: "https://pds.example.com",
            repositoryRevision: "3lqby3xuo4k2a",
            operationCID: genesisCID,
            stage: .submitted
        )
        _ = try await database.reservePLCAccountPreparationIntent(
            try PLCAccountPreparationIntent(
                requestID: staging.requestID,
                did: staging.did,
                canonicalHandle: staging.canonicalHandle,
                pdsOrigin: staging.pdsOrigin,
                repositoryRevision: staging.repositoryRevision,
                operationCID: staging.operationCID,
                stage: .keysStored
            )
        )
        _ = try await database.advancePLCAccountPreparationIntent(
            requestID: staging.requestID,
            expectedStage: .keysStored,
            to: .repositoryInstalled
        )
        _ = try await database.advancePLCAccountPreparationIntent(
            requestID: staging.requestID,
            expectedStage: .repositoryInstalled,
            to: .submissionPending
        )
        _ = try await database.advancePLCAccountPreparationIntent(
            requestID: staging.requestID,
            expectedStage: .submissionPending,
            to: .submitted
        )

        let declaration = AccountLifecycleDeclaration(
            tombstone: try AccountTombstoneMetadata(
                declaredAt: createdAt.addingTimeInterval(10.123456789),
                reason: "user-request"
            ),
            export: try AccountExportMetadata(
                declaredAt: createdAt.addingTimeInterval(9.987654321),
                reference: "sha256:" + String(repeating: "a", count: 64)
            )
        )
        // Roll the wall clock backwards deliberately. The durable revision
        // must still advance from the account's existing revision.
        let begun = try await database.beginDeletion(
            did: did,
            declaration: declaration,
            now: createdAt.addingTimeInterval(-10)
        )
        XCTAssertEqual(begun.stage, .controlScrubbed)
        XCTAssertEqual(begun.rotationKey?.generation, 3)
        XCTAssertEqual(
            begun.rotationKey?.reference,
            "account-rotation:3"
        )
        XCTAssertGreaterThan(
            begun.revision,
            UInt64(createdAt.timeIntervalSince1970 * 1_000_000)
        )
        XCTAssertEqual(
            begun.stagingKeyBindings,
            [
                try AccountDeletionStagingKeyBinding(
                    requestID: staging.requestID,
                    canonicalHandle: staging.canonicalHandle,
                    pdsOrigin: staging.pdsOrigin,
                    repositoryRevision: staging.repositoryRevision
                ),
            ]
        )

        let loadedAccount = try await database.account(did: did)
        let account = try XCTUnwrap(loadedAccount)
        XCTAssertEqual(account.status, .deleting)
        XCTAssertEqual(account.credentialState, .missing)
        XCTAssertNil(account.signingKey)
        XCTAssertNil(account.rotationKey)
        XCTAssertNil(account.publicGenesisCommitCID)
        XCTAssertNotEqual(account.canonicalHandle, "delete-me.example.com")
        XCTAssertTrue(account.canonicalHandle.hasSuffix(".invalid"))
        let oldHandleAccount = try await database.account(
            canonicalHandle: "delete-me.example.com"
        )
        XCTAssertNil(oldHandleAccount)
        let deletedCredential = try await database.credential(did: did)
        XCTAssertNil(deletedCredential)
        let activeDIDs = try await database.activeAccountDIDs()
        XCTAssertFalse(activeDIDs.contains(did))

        for tableAndPredicate in [
            ("oauth_tokens", "subject = ?"),
            ("oauth_control_token_families", "subject = ?"),
            ("account_emails", "did = ?"),
            ("account_email_tokens", "did = ?"),
            ("account_email_delivery_outbox", "did = ?"),
            ("plc_account_preparation_intents", "did = ?"),
            ("plc_credential_key_continuity", "issuer = ?"),
        ] {
            let rows = try await database.connection.query(
                "SELECT 1 FROM \(tableAndPredicate.0) WHERE \(tableAndPredicate.1)",
                [.text(did)]
            )
            XCTAssertTrue(rows.isEmpty, "\(tableAndPredicate.0) retained deleted-account state")
        }
        let otherFamilyRows = try await database.connection.query(
            "SELECT 1 FROM oauth_control_token_families WHERE subject = ?",
            [.text(otherDID)]
        )
        XCTAssertEqual(otherFamilyRows.count, 1)
        let retainedDeliveryRows = try await database.connection.query(
            """
            SELECT delivery_id, did
            FROM account_email_delivery_outbox
            ORDER BY delivery_id
            """
        )
        XCTAssertEqual(retainedDeliveryRows.count, 1)
        XCTAssertEqual(
            retainedDeliveryRows.first?.column("delivery_id")?.string,
            retainedDeliveryID
        )
        XCTAssertEqual(
            retainedDeliveryRows.first?.column("did")?.string,
            otherDID
        )
        for table in [
            "oauth_control_authorization_codes",
            "oauth_control_access_tokens",
            "oauth_control_refresh_tokens",
        ] {
            let deletedRows = try await database.connection.query(
                "SELECT 1 FROM \(table) WHERE family_id = ?",
                [.text("11111111-1111-1111-1111-111111111111")]
            )
            let retainedRows = try await database.connection.query(
                "SELECT 1 FROM \(table) WHERE family_id = ?",
                [.text("22222222-2222-2222-2222-222222222222")]
            )
            XCTAssertTrue(deletedRows.isEmpty)
            XCTAssertEqual(retainedRows.count, 1)
        }
        let otherContinuityRows = try await database.connection.query(
            "SELECT 1 FROM plc_credential_key_continuity WHERE issuer = ?",
            [.text(otherDID)]
        )
        XCTAssertEqual(otherContinuityRows.count, 1)
        let otherCredential = try await database.credential(did: otherDID)
        XCTAssertNotNil(otherCredential)

        // beginDeletion is idempotent and must not rewrite the revision.
        let retried = try await database.beginDeletion(
            did: did,
            declaration: declaration,
            now: createdAt.addingTimeInterval(100)
        )
        XCTAssertEqual(retried, begun)
        try await database.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        let reopenedJob = try await reopened.deletionJob(did: did)
        XCTAssertEqual(reopenedJob, begun)
        XCTAssertEqual(reopenedJob?.rotationKey?.generation, 3)
        let pending = try await reopened.pendingDeletionJobs(
            afterDID: nil,
            limit: 10
        )
        XCTAssertEqual(pending, [begun])
        let reopenedOther = try await reopened.account(did: otherDID)
        XCTAssertNotNil(reopenedOther)
        let plc = try await reopened.advanceDeletion(
            did: did,
            expectedStage: .controlScrubbed,
            expectedRevision: begun.revision,
            to: .plcTombstoned,
            now: createdAt
        )
        XCTAssertEqual(plc.stagingKeyBindings, begun.stagingKeyBindings)
        XCTAssertEqual(plc.rotationKey, begun.rotationKey)
        let keys = try await reopened.advanceDeletion(
            did: did,
            expectedStage: .plcTombstoned,
            expectedRevision: plc.revision,
            to: .keyMaterialDestroyed,
            now: createdAt
        )
        XCTAssertTrue(keys.stagingKeyBindings.isEmpty)
        XCTAssertNil(keys.rotationKey)
        try await reopened.close()
    }

    func testDeletionStagesAreOrderedMonotonicAndFinalizeToMinimalTombstone() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let now = Date(timeIntervalSince1970: 1_750_000_200)
        _ = try await database.createAccount(
            try registration(did: did, handle: "ordered.example.com", createdAt: now)
        )
        await XCTAssertThrowsErrorAsync(
            try await database.transitionStatus(
                did: did,
                to: .deleting,
                declaration: .init(),
                now: now
            )
        ) { error in
            XCTAssertEqual(
                error as? AccountControlStoreError,
                .invalidTransition
            )
        }
        await XCTAssertThrowsErrorAsync(
            try await database.transitionStatus(
                did: did,
                to: .deleted,
                declaration: AccountLifecycleDeclaration(
                    tombstone: try AccountTombstoneMetadata(
                        declaredAt: now,
                        reason: "must-use-deletion-coordinator"
                    )
                ),
                now: now
            )
        ) { error in
            XCTAssertEqual(
                error as? AccountControlStoreError,
                .invalidTransition
            )
        }
        let stillActive = try await database.account(did: did)
        XCTAssertEqual(stillActive?.status, .active)
        let declaration = AccountLifecycleDeclaration(
            tombstone: try AccountTombstoneMetadata(
                declaredAt: now,
                reason: "operator-request"
            )
        )
        let begun = try await database.beginDeletion(
            did: did,
            declaration: declaration,
            now: now
        )

        await XCTAssertThrowsErrorAsync(
            try await database.advanceDeletion(
                did: did,
                expectedStage: .controlScrubbed,
                expectedRevision: begun.revision,
                to: .keyMaterialDestroyed,
                now: now
            )
        ) { error in
            XCTAssertEqual(error as? AccountDeletionStoreError, .invalidStage)
        }
        await XCTAssertThrowsErrorAsync(
            try await database.finalizeDeletion(
                did: did,
                expectedRevision: begun.revision,
                now: now
            )
        ) { error in
            XCTAssertEqual(error as? AccountDeletionStoreError, .invalidStage)
        }

        let plc = try await database.advanceDeletion(
            did: did,
            expectedStage: .controlScrubbed,
            expectedRevision: begun.revision,
            to: .plcTombstoned,
            now: now.addingTimeInterval(-100)
        )
        XCTAssertGreaterThan(plc.revision, begun.revision)
        XCTAssertEqual(plc.rotationKey?.generation, 3)
        let keys = try await database.advanceDeletion(
            did: did,
            expectedStage: .plcTombstoned,
            expectedRevision: plc.revision,
            to: .keyMaterialDestroyed,
            now: now.addingTimeInterval(-100)
        )
        XCTAssertGreaterThan(keys.revision, plc.revision)
        XCTAssertNil(keys.rotationKey)
        let accountData = try await database.advanceDeletion(
            did: did,
            expectedStage: .keyMaterialDestroyed,
            expectedRevision: keys.revision,
            to: .accountDataDestroyed,
            now: now.addingTimeInterval(-100)
        )
        XCTAssertTrue(accountData.stage.isFinalizable)
        XCTAssertGreaterThan(accountData.revision, keys.revision)

        // A retry after an uncertain write returns the exact advanced job.
        let retriedAccountData = try await database.advanceDeletion(
            did: did,
            expectedStage: .keyMaterialDestroyed,
            expectedRevision: keys.revision,
            to: .accountDataDestroyed,
            now: now.addingTimeInterval(500)
        )
        XCTAssertEqual(retriedAccountData, accountData)
        let tombstone = try await database.finalizeDeletion(
            did: did,
            expectedRevision: accountData.revision,
            now: now.addingTimeInterval(-100)
        )
        XCTAssertEqual(tombstone.did, did)
        XCTAssertEqual(tombstone.tombstone.reason, "operator-request")
        XCTAssertNil(tombstone.export)
        XCTAssertGreaterThan(tombstone.revision, accountData.revision)
        let finalizedAccount = try await database.account(did: did)
        let finalizedJob = try await database.deletionJob(did: did)
        let storedTombstone = try await database.tombstone(did: did)
        XCTAssertNil(finalizedAccount)
        XCTAssertNil(finalizedJob)
        XCTAssertEqual(storedTombstone, tombstone)
        let retriedTombstone = try await database.finalizeDeletion(
            did: did,
            expectedRevision: accountData.revision,
            now: now.addingTimeInterval(999)
        )
        XCTAssertEqual(retriedTombstone, tombstone)
        await XCTAssertThrowsErrorAsync(
            try await database.createAccount(
                self.registration(
                    did: self.did,
                    handle: "resurrection.example.com",
                    createdAt: now.addingTimeInterval(1)
                )
            )
        ) { error in
            XCTAssertEqual(error as? AccountControlStoreError, .duplicateDID)
        }

        let columns = try await database.connection.query(
            "PRAGMA table_info(account_deletion_tombstones)"
        ).compactMap { $0.column("name")?.string }
        XCTAssertEqual(
            Set(columns),
            Set([
                "did", "finalized_at", "revision", "tombstone_declared_at",
                "tombstone_reason", "export_declared_at", "export_reference",
            ])
        )
        XCTAssertFalse(columns.contains("handle"))
        XCTAssertFalse(columns.contains("password_verifier"))
        XCTAssertFalse(columns.contains("key_reference"))
        XCTAssertFalse(columns.contains("public_genesis_commit_cid"))
        try await database.close()
    }

    func testBeginDeletionRejectsUnrepresentableTimestampWithoutTrapping()
        async throws
    {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }
        let createdAt = Date(timeIntervalSince1970: 1_750_000_250)
        _ = try await database.createAccount(
            try registration(
                did: did,
                handle: "timestamp-bound.example.com",
                createdAt: createdAt
            )
        )

        await XCTAssertThrowsErrorAsync(
            try await database.beginDeletion(
                did: did,
                declaration: .init(),
                now: Date(
                    timeIntervalSince1970:
                        Double(Int.max) / 1_000_000
                )
            )
        ) { error in
            XCTAssertEqual(
                error as? AccountDeletionStoreError,
                .invalidInput
            )
        }
        let retainedAccount = try await database.account(did: did)
        let deletionJob = try await database.deletionJob(did: did)
        XCTAssertEqual(retainedAccount?.status, .active)
        XCTAssertNil(deletionJob)
    }

    func testLegacyDeletedRowIsMigratedIntoResumableScrubbedJob() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let first = try await SQLiteControlDatabase(dataDirectory: root)
        let now = Date(timeIntervalSince1970: 1_750_000_300)
        _ = try await first.createAccount(
            try registration(did: did, handle: "legacy-delete.example.com", createdAt: now)
        )
        _ = try await first.connection.query(
            """
            UPDATE accounts
            SET status = 'deleted',
                tombstone_declared_at = ?,
                tombstone_reason = 'legacy-request'
            WHERE did = ?
            """,
            [.integer(Int(now.timeIntervalSince1970 * 1_000_000)), .text(did)]
        )
        try await first.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        let loadedAccount = try await reopened.account(did: did)
        let account = try XCTUnwrap(loadedAccount)
        XCTAssertEqual(account.status, .deleting)
        XCTAssertEqual(account.credentialState, .missing)
        XCTAssertNil(account.signingKey)
        XCTAssertNil(account.rotationKey)
        XCTAssertNil(account.publicGenesisCommitCID)
        let loadedJob = try await reopened.deletionJob(did: did)
        let job = try XCTUnwrap(loadedJob)
        XCTAssertEqual(job.stage, .controlScrubbed)
        XCTAssertEqual(job.tombstone.reason, "legacy-request")
        try await reopened.close()
    }

    func testFinalizationRejectsResidualTrustAndCorruptStagesFailClosed() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let now = Date(timeIntervalSince1970: 1_750_000_400)
        _ = try await database.createAccount(
            try registration(did: did, handle: "corrupt.example.com", createdAt: now)
        )
        var job = try await database.beginDeletion(
            did: did,
            declaration: .init(),
            now: now
        )
        for destination: AccountDeletionStage in [
            .plcTombstoned,
            .keyMaterialDestroyed,
            .accountDataDestroyed,
        ] {
            let source = job.stage
            job = try await database.advanceDeletion(
                did: did,
                expectedStage: source,
                expectedRevision: job.revision,
                to: destination,
                now: now
            )
        }
        _ = try await database.connection.query(
            "UPDATE accounts SET password_verifier = ? WHERE did = ?",
            [.text(verifier), .text(did)]
        )
        await XCTAssertThrowsErrorAsync(
            try await database.finalizeDeletion(
                did: did,
                expectedRevision: job.revision,
                now: now
            )
        ) { error in
            XCTAssertEqual(error as? AccountDeletionStoreError, .malformedRecord)
        }
        let residualAccount = try await database.account(did: did)
        let residualJob = try await database.deletionJob(did: did)
        XCTAssertNotNil(residualAccount)
        XCTAssertNotNil(residualJob)

        _ = try await database.connection.query("PRAGMA ignore_check_constraints=ON")
        _ = try await database.connection.query(
            "UPDATE account_deletion_jobs SET stage = 'fabricated' WHERE did = ?",
            [.text(did)]
        )
        await XCTAssertThrowsErrorAsync(
            try await database.deletionJob(did: did)
        ) { error in
            XCTAssertEqual(error as? AccountDeletionStoreError, .malformedRecord)
        }
        try await database.close()
    }

    private func registration(
        did: String,
        handle: String,
        createdAt: Date
    ) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: verifier,
            signingKey: AccountControlKeyReference(
                purpose: .signing,
                generation: 3
            ),
            rotationKey: AccountControlKeyReference(
                purpose: .rotation,
                generation: 3
            ),
            publicGenesisCommitCID: genesisCID,
            createdAt: createdAt
        )
    }

    private func seedEmailAndOAuth(
        in database: SQLiteControlDatabase,
        now: Date
    ) async throws {
        let deletedEmail = try AccountEmailAddress("delete-me@example.com")
        let retainedEmail = try AccountEmailAddress("keep-me@example.com")
        try await database.associateEmail(
            did: did,
            email: deletedEmail,
            now: now
        )
        try await database.associateEmail(
            did: otherDID,
            email: retainedEmail,
            now: now
        )
        let deletedDelivery = try AccountEmailProofDeliveryRequest(
            deliveryID: AccountEmailDeliveryID(
                rawValue: deletedDeliveryID
            ),
            did: did,
            email: deletedEmail,
            purpose: .verifyEmail,
            proofDigest: Data(repeating: 0x31, count: 32),
            expiresAt: now.addingTimeInterval(600),
            now: now
        )
        let retainedDelivery = try AccountEmailProofDeliveryRequest(
            deliveryID: AccountEmailDeliveryID(
                rawValue: retainedDeliveryID
            ),
            did: otherDID,
            email: retainedEmail,
            purpose: .verifyEmail,
            proofDigest: Data(repeating: 0x32, count: 32),
            expiresAt: now.addingTimeInterval(600),
            now: now
        )
        let deletedDeliveryOutcome =
            try await database.enqueueEmailProofDelivery(deletedDelivery)
        XCTAssertEqual(deletedDeliveryOutcome, .enqueued)
        let retainedDeliveryOutcome =
            try await database.enqueueEmailProofDelivery(retainedDelivery)
        XCTAssertEqual(retainedDeliveryOutcome, .enqueued)
        for (subject, familyID, marker) in [
            (did, "11111111-1111-1111-1111-111111111111", UInt8(0x41)),
            (otherDID, "22222222-2222-2222-2222-222222222222", UInt8(0x51)),
        ] {
            _ = try await database.connection.query(
                """
                INSERT INTO oauth_tokens(
                    digest, family_id, subject, expires_at, revoked
                ) VALUES (?, ?, ?, ?, 0)
                """,
                [
                    Data(repeating: marker, count: 32).sqliteData!,
                    .text(familyID), .text(subject),
                    .integer(Int((now.timeIntervalSince1970 + 600) * 1_000_000)),
                ]
            )
            _ = try await database.connection.query(
                """
                INSERT INTO oauth_control_token_families(
                    family_id, subject, issuer, client_id, redirect_uri, scopes,
                    dpop_jkt, client_assertion_key_id,
                    client_assertion_algorithm, client_assertion_jkt,
                    refresh_token_allowed, expires_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, 1, ?, NULL)
                """,
                [
                    .text(familyID), .text(subject), .text(subject),
                    .text("https://client.example/\(marker)"),
                    .text("https://client.example/callback"),
                    Data("atproto".utf8).sqliteData!,
                    .integer(Int((now.timeIntervalSince1970 + 600) * 1_000_000)),
                ]
            )
            _ = try await database.connection.query(
                """
                INSERT INTO oauth_control_authorization_codes(
                    code_digest, family_id, code_challenge_method,
                    code_challenge_s256, expires_at, reuse_expires_at,
                    consumed_at
                ) VALUES (?, ?, 'S256', ?, ?, ?, NULL)
                """,
                [
                    Data(repeating: marker &+ 1, count: 32).sqliteData!,
                    .text(familyID), .text(String(repeating: "a", count: 43)),
                    .integer(Int((now.timeIntervalSince1970 + 300) * 1_000_000)),
                    .integer(Int((now.timeIntervalSince1970 + 600) * 1_000_000)),
                ]
            )
            _ = try await database.connection.query(
                """
                INSERT INTO oauth_control_access_tokens(
                    token_digest, family_id, expires_at
                ) VALUES (?, ?, ?)
                """,
                [
                    Data(repeating: marker &+ 2, count: 32).sqliteData!,
                    .text(familyID),
                    .integer(Int((now.timeIntervalSince1970 + 300) * 1_000_000)),
                ]
            )
            _ = try await database.connection.query(
                """
                INSERT INTO oauth_control_refresh_tokens(
                    token_digest, family_id, expires_at, used_at
                ) VALUES (?, ?, ?, NULL)
                """,
                [
                    Data(repeating: marker &+ 3, count: 32).sqliteData!,
                    .text(familyID),
                    .integer(Int((now.timeIntervalSince1970 + 600) * 1_000_000)),
                ]
            )
        }
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "swan-permanent-deletion-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ errorHandler: (any Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("expected expression to throw")
    } catch {
        errorHandler(error)
    }
}
