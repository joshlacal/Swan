import Crypto
import Foundation
import Petrel
import PetrelCrypto
import PetrelFirehose
import PetrelRepo
import SQLiteNIO
import SwanCore
@_spi(PortableRestore) @testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class SwanSQLiteTests: XCTestCase {
    func testEmailProofIsHashOnlySingleUseAndExpires() async throws {
        let root = try controlRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        _ = try await database.createAccount(controlRegistration(did: did, handle: "email.example.com"))
        let email = try AccountEmailAddress("person@example.com")
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        try await database.associateEmail(did: did, email: email, now: now)
        let token = Data(repeating: 0x42, count: 32)
        try await database.issueEmailToken(
            did: did,
            email: email,
            purpose: .verifyEmail,
            digest: token,
            expiresAt: now.addingTimeInterval(60),
            now: now
        )
        let persisted = try await database.connection.query(
            "SELECT digest, email, purpose FROM account_email_tokens"
        )
        XCTAssertEqual(persisted.count, 1)
        XCTAssertEqual(
            Data(sqliteData: try XCTUnwrap(persisted[0].column("digest"))),
            token
        )
        XCTAssertEqual(persisted[0].column("email")?.string, email.value)
        XCTAssertEqual(
            persisted[0].column("purpose")?.string,
            AccountEmailTokenPurpose.verifyEmail.rawValue
        )
        // A wrong-purpose attempt is indistinguishable from an unknown proof
        // and must not burn the correctly scoped token.
        let wrongPurpose = try await database.consumeEmailToken(
            digest: token,
            purpose: .passwordRecovery,
            now: now
        )
        XCTAssertNil(wrongPurpose)
        let consumed = try await database.consumeEmailToken(digest: token, purpose: .verifyEmail, now: now)
        XCTAssertEqual(consumed, did)
        let verifiedEmail = try await database.verifiedEmail(did: did)
        XCTAssertEqual(verifiedEmail, email)
        let replay = try await database.consumeEmailToken(digest: token, purpose: .verifyEmail, now: now)
        XCTAssertNil(replay)
        let expired = Data(repeating: 0x43, count: 32)
        try await database.issueEmailToken(
            did: did,
            email: email,
            purpose: .passwordRecovery,
            digest: expired,
            expiresAt: now.addingTimeInterval(1),
            now: now
        )
        let expiredResult = try await database.consumeEmailToken(digest: expired, purpose: .passwordRecovery, now: now.addingTimeInterval(2))
        XCTAssertNil(expiredResult)
        try await database.close()
    }

    func testEmailProofIsBoundToAddressGeneration() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        _ = try await database.createAccount(
            controlRegistration(did: did, handle: "email-generation.example.com")
        )
        let firstEmail = try AccountEmailAddress("first@example.com")
        let secondEmail = try AccountEmailAddress("second@example.com")
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let firstToken = Data(repeating: 0x51, count: 32)
        try await database.associateEmail(did: did, email: firstEmail, now: now)
        try await database.issueEmailToken(
            did: did,
            email: firstEmail,
            purpose: .verifyEmail,
            digest: firstToken,
            expiresAt: now.addingTimeInterval(600),
            now: now
        )

        try await database.associateEmail(
            did: did,
            email: secondEmail,
            now: now.addingTimeInterval(1)
        )
        let oldAddressResult = try await database.consumeEmailToken(
            digest: firstToken,
            purpose: .verifyEmail,
            now: now.addingTimeInterval(2)
        )
        XCTAssertNil(oldAddressResult)
        let verifiedAfterReassociation = try await database.verifiedEmail(did: did)
        XCTAssertNil(verifiedAfterReassociation)

        // A caller which selected the old destination before reassociation
        // cannot create a usable proof for that stale delivery address.
        await XCTAssertThrowsErrorAsync(
            try await database.issueEmailToken(
                did: did,
                email: firstEmail,
                purpose: .verifyEmail,
                digest: Data(repeating: 0x52, count: 32),
                expiresAt: now.addingTimeInterval(600),
                now: now.addingTimeInterval(2)
            )
        ) { error in
            XCTAssertEqual(error as? AccountControlStoreError, .notFound)
        }

        // Returning to the same textual address is still a new generation;
        // the proof issued for its earlier generation remains revoked.
        try await database.associateEmail(
            did: did,
            email: firstEmail,
            now: now.addingTimeInterval(3)
        )
        let earlierGenerationResult = try await database.consumeEmailToken(
            digest: firstToken,
            purpose: .verifyEmail,
            now: now.addingTimeInterval(4)
        )
        XCTAssertNil(earlierGenerationResult)
        try await database.close()
    }

    func testEmailProofAndCredentialReplacementFailForInactiveAccount() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        _ = try await database.createAccount(
            controlRegistration(did: did, handle: "inactive-recovery.example.com")
        )
        let email = try AccountEmailAddress("person@example.com")
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let token = Data(repeating: 0x61, count: 32)
        try await database.associateEmail(did: did, email: email, now: now)
        try await database.issueEmailToken(
            did: did,
            email: email,
            purpose: .passwordRecovery,
            digest: token,
            expiresAt: now.addingTimeInterval(600),
            now: now
        )
        let loadedCredential = try await database.credential(did: did)
        let credential = try XCTUnwrap(loadedCredential)
        _ = try await database.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: AccountLifecycleDeclaration(),
            now: now.addingTimeInterval(1)
        )

        let deactivatedResult = try await database.consumeEmailToken(
            digest: token,
            purpose: .passwordRecovery,
            now: now.addingTimeInterval(2)
        )
        XCTAssertNil(deactivatedResult)
        let replacement = try await database.replaceCredential(
            did: did,
            expectedVerifier: credential.verifier,
            replacementVerifier: credential.verifier,
            now: now.addingTimeInterval(2)
        )
        XCTAssertEqual(replacement, .unchanged)
        await XCTAssertThrowsErrorAsync(
            try await database.issueEmailToken(
                did: did,
                email: email,
                purpose: .passwordRecovery,
                digest: Data(repeating: 0x62, count: 32),
                expiresAt: now.addingTimeInterval(600),
                now: now.addingTimeInterval(2)
            )
        ) { error in
            XCTAssertEqual(error as? AccountControlStoreError, .notFound)
        }

        // Reactivation does not resurrect proofs revoked at the lifecycle
        // boundary.
        _ = try await database.transitionStatus(
            did: did,
            to: .active,
            declaration: AccountLifecycleDeclaration(),
            now: now.addingTimeInterval(3)
        )
        let reactivatedResult = try await database.consumeEmailToken(
            digest: token,
            purpose: .passwordRecovery,
            now: now.addingTimeInterval(4)
        )
        XCTAssertNil(reactivatedResult)
        _ = try await database.beginDeletion(
            did: did,
            declaration: AccountLifecycleDeclaration(
                tombstone: try AccountTombstoneMetadata(
                    declaredAt: now.addingTimeInterval(5),
                    reason: "email-lifecycle-test"
                )
            ),
            now: now.addingTimeInterval(5)
        )
        let deletedEmail = try await database.associatedEmail(did: did)
        XCTAssertNil(deletedEmail)
        try await database.close()
    }

    func testEmailProofConcurrentConsumptionAcrossConnectionsHasOneWinner() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let first = try await SQLiteControlDatabase(dataDirectory: root)
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        _ = try await first.createAccount(
            controlRegistration(did: did, handle: "email-race.example.com")
        )
        let email = try AccountEmailAddress("person@example.com")
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let token = Data(repeating: 0x71, count: 32)
        try await first.associateEmail(did: did, email: email, now: now)
        try await first.issueEmailToken(
            did: did,
            email: email,
            purpose: .verifyEmail,
            digest: token,
            expiresAt: now.addingTimeInterval(600),
            now: now
        )
        let second = try await SQLiteControlDatabase(dataDirectory: root)

        async let firstClaim = first.consumeEmailToken(
            digest: token,
            purpose: .verifyEmail,
            now: now.addingTimeInterval(1)
        )
        async let secondClaim = second.consumeEmailToken(
            digest: token,
            purpose: .verifyEmail,
            now: now.addingTimeInterval(1)
        )
        let claims = try await (firstClaim, secondClaim)
        XCTAssertEqual([claims.0, claims.1].compactMap { $0 }, [did])

        try await first.close()
        try await second.close()
    }

    func testEmailProofMigrationInvalidatesUnboundLegacyTokens() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await database.createAccount(
            controlRegistration(did: did, handle: "email-migration.example.com")
        )
        try await database.associateEmail(
            did: did,
            email: try AccountEmailAddress("person@example.com"),
            now: now
        )
        try await database.close()

        let path = SQLiteLayout.controlDatabase(in: root).path
        let legacy = try await SQLiteConnection.open(storage: .file(path: path))
        _ = try await legacy.query("DROP TABLE account_email_tokens")
        _ = try await legacy.query(
            """
            CREATE TABLE account_email_tokens (
                digest BLOB PRIMARY KEY CHECK(length(digest) = 32),
                did TEXT NOT NULL REFERENCES accounts(did) ON DELETE CASCADE,
                purpose TEXT NOT NULL CHECK(purpose IN ('verify-email', 'password-recovery')),
                expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
                consumed_at INTEGER CHECK(consumed_at >= 0)
            )
            """
        )
        _ = try await legacy.query(
            """
            INSERT INTO account_email_tokens(
                digest, did, purpose, expires_at, consumed_at
            ) VALUES (?, ?, 'verify-email', ?, NULL)
            """,
            [
                Data(repeating: 0x81, count: 32).sqliteData!,
                .text(did),
                .integer(1_750_000_600_000_000),
            ]
        )
        try await legacy.close()

        let migrated = try await SQLiteControlDatabase(dataDirectory: root)
        let rows = try await migrated.connection.query(
            "SELECT digest FROM account_email_tokens"
        )
        XCTAssertTrue(rows.isEmpty)
        let columns = try await migrated.connection.query(
            "PRAGMA table_info(account_email_tokens)"
        )
        XCTAssertTrue(columns.contains {
            $0.column("name")?.string == "email"
        })
        try await migrated.close()
    }

    func testOperatorRestoreRejectsClientAttestationReplayState() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        _ = try await database.createAccount(
            controlRegistration(did: did, handle: "restore.example.com")
        )
        let claimed = try await database.claimSpaceClientAttestation(
            digest: Data(repeating: 0xA7, count: 32),
            expiresAt: Date(timeIntervalSince1970: 1_750_000_120),
            now: Date(timeIntervalSince1970: 1_750_000_000)
        )
        XCTAssertTrue(claimed)
        await XCTAssertThrowsErrorAsync(
            try await database.validateOperatorRestoreOnlyAccount(did: did)
        ) { error in
            XCTAssertEqual(error as? AccountControlStoreError, .malformedRecord)
        }
        try await database.close()
    }

    func testPortableExportDatabaseModesRejectDurableWrites() async throws {
        let fixture = try Fixture()
        let managedAccount = try await fixture.open()
        try await managedAccount.close()
        let managedControl = try await SQLiteControlDatabase(dataDirectory: fixture.root)
        try await managedControl.close()

        let account = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root,
            did: fixture.author,
            openMode: .existingPortableExportSource
        )
        do {
            _ = try await account.connection.query(
                "CREATE TABLE portable_export_must_not_write(value INTEGER)"
            )
            XCTFail("portable export account connection accepted a write")
        } catch {}
        // CAR export uses a connection-local index to keep durable repository
        // writes impossible without preventing its bounded snapshot path.
        _ = try await account.connection.query(
            "CREATE TEMP TABLE portable_export_temp_index(value INTEGER)"
        )
        _ = try await account.connection.query(
            "DROP TABLE portable_export_temp_index"
        )
        try await account.close()

        let control = try await SQLiteControlDatabase(
            dataDirectory: fixture.root,
            openMode: .existingPortableExportSource
        )
        do {
            _ = try await control.connection.query(
                "CREATE TABLE portable_export_must_not_write(value INTEGER)"
            )
            XCTFail("portable export control connection accepted a write")
        } catch {}
        try await control.close()
    }

    func testRestartPreservesRepositoryRecordsOplogAndPendingOutbox() async throws {
        let fixture = try Fixture()
        var database: SQLiteAccountDatabase? = try await fixture.open()

        let result = try await database!.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 0,
            requestID: UUID(uuidString: "10000000-0000-0000-0000-000000000001")!,
            wireRevision: try fixture.tid(0),
            writes: [.put(uri: fixture.first, value: fixture.firstValue, cid: fixture.firstCID)],
            eventID: UUID(uuidString: "20000000-0000-0000-0000-000000000001")!
        )
        XCTAssertEqual(result.state.revision, 1)
        XCTAssertEqual(
            result.outbox.payload,
            Data(result.outbox.id.uuidString.lowercased().utf8)
        )
        XCTAssertNil(result.outbox.payload.range(of: fixture.firstValue))
        try await database!.close()
        database = nil

        let reopened = try await fixture.open()
        try await withClosedAccountDatabase(reopened) { reopened in
            let loadedSnapshot = try await reopened.repositorySnapshot(
                space: fixture.space,
                author: fixture.author
            )
            let snapshot = try XCTUnwrap(loadedSnapshot)
            XCTAssertEqual(snapshot.state.revision, 1)
            XCTAssertEqual(snapshot.state.ltHash.count, LtHash.byteCount)
            XCTAssertEqual(snapshot.state.commit, result.state.commit)
            XCTAssertNotEqual(snapshot.state.commit, Data([0x00, 0xff, 0x42]))
            XCTAssertEqual(snapshot.records.map(\.value), [fixture.firstValue])
            XCTAssertEqual(snapshot.records.map(\.cid), [fixture.firstCID])

            let oplog = try await reopened.spaceOplog(
                space: fixture.space,
                author: fixture.author,
                since: 0
            )
            guard case let .incremental(entries) = oplog else {
                return XCTFail("revision zero should still be inside retention")
            }
            XCTAssertEqual(entries.count, 1)
            XCTAssertEqual(entries.first?.revision, 1)

            let pending = try await reopened.pendingOutbox()
            XCTAssertEqual(pending, [result.outbox])
        }
    }

    func testPermissionedStorageRejectsOversizedWriteBatchBeforeTransaction() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close(); try? FileManager.default.removeItem(at: fixture.root) } }

        let writes = try (0...SpaceWriteLimits.maximumOperations).map { index in
            let uri = try SpaceRecordURI(
                space: fixture.space,
                author: fixture.author,
                collection: "app.bsky.feed.post",
                rkey: "r\(index)"
            )
            return SQLiteSpaceWrite.put(
                uri: uri,
                value: fixture.firstValue,
                cid: fixture.firstCID
            )
        }

        await XCTAssertThrowsErrorAsync(
            try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try fixture.tid(0),
                writes: writes
            )
        ) { error in
            guard case SwanError.malformed = error else {
                return XCTFail("an oversized direct storage batch must fail closed")
            }
        }
        let state = try await database.repositoryState(
            space: fixture.space,
            author: fixture.author
        )
        XCTAssertNil(state)
    }

    func testWireOplogBoundsValueMaterializationAtAggregateBudget() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close(); try? FileManager.default.removeItem(at: fixture.root) } }

        func largeValue(_ byte: UInt8) -> Data {
            Data([0xa1, 0x61, 0x76, 0x59, 0x02, 0xbc])
                + Data(repeating: byte, count: 700)
        }
        let firstURI = try SpaceRecordURI(
            space: fixture.space,
            author: fixture.author,
            collection: "app.bsky.feed.post",
            rkey: "large-first"
        )
        let secondURI = try SpaceRecordURI(
            space: fixture.space,
            author: fixture.author,
            collection: "app.bsky.feed.post",
            rkey: "large-second"
        )
        let firstValue = largeValue(0x01)
        let secondValue = largeValue(0x02)
        _ = try await database.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try fixture.tid(0),
            writes: [.put(uri: firstURI, value: firstValue, cid: CID.fromDAGCBOR(firstValue).string)]
        )
        _ = try await database.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 1,
            requestID: UUID(),
            wireRevision: try fixture.tid(1),
            writes: [.put(uri: secondURI, value: secondValue, cid: CID.fromDAGCBOR(secondValue).string)]
        )

        let read = try await database.wireOplog(
            space: fixture.space,
            author: fixture.author,
            since: nil,
            limit: 100,
            includeValues: true,
            maximumAggregateValueBytes: 800
        )
        guard case let .incremental(_, entries) = read else {
            return XCTFail("a retained oplog must return an incremental page")
        }
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries.first?.value?.count, firstValue.count)
    }

    func testWireOplogRejectsOversizedAtomicBatchBeforeValueMaterialization() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close(); try? FileManager.default.removeItem(at: fixture.root) } }

        let value = Data([0xa1, 0x61, 0x76, 0x01])
        let cid = CID.fromDAGCBOR(value).string
        // Keep this at the shared mutation ceiling while still creating a
        // same-TID group larger than the requested oplog page. The read path
        // must reject the group before selecting its value BLOBs; the write
        // path rejects only batches above the domain admission limit.
        let writes = try (0 ..< SpaceWriteLimits.maximumOperations)
            .map { index in
                let uri = try SpaceRecordURI(
                    space: fixture.space,
                    author: fixture.author,
                    collection: "app.bsky.feed.post",
                    rkey: "r\(index)"
                )
                return SQLiteSpaceWrite.put(uri: uri, value: value, cid: cid)
            }
        _ = try await database.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try fixture.tid(0),
            writes: writes
        )

        let probe = WireOplogMaterializationProbe()
        await database.installTestingHooks(
            SQLiteTestingHooks(beforeWireOplogValueMaterialization: {
                await probe.mark()
            })
        )
        await XCTAssertThrowsErrorAsync(
            try await database.wireOplog(
                space: fixture.space,
                author: fixture.author,
                since: nil,
                limit: 1,
                includeValues: true,
                maximumAggregateValueBytes: 1
            )
        ) { error in
            guard case SwanError.unavailable = error else {
                return XCTFail("oversized same-TID batch must fail as unavailable")
            }
        }
        let materializationRan = await probe.didRun()
        XCTAssertFalse(materializationRan)
    }

    func testPermissionedStorageRejectsNonCanonicalOrMismatchedRecordBeforeMutation()
        async throws
    {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }

        let nonCanonical = Data([0xa1, 0x61, 0x7a, 0x18, 0x01])
        let nonCanonicalCID =
            String(fixture.firstCID.prefix(1))
            + fixture.firstCID.dropFirst().uppercased()
        XCTAssertNotEqual(nonCanonicalCID, fixture.firstCID)
        XCTAssertEqual(
            try CID.parse(nonCanonicalCID),
            try CID.parse(fixture.firstCID)
        )
        for (value, cid) in [
            (nonCanonical, CID.fromDAGCBOR(nonCanonical).string),
            (fixture.firstValue, fixture.secondCID),
            (fixture.firstValue, nonCanonicalCID),
        ] {
            await XCTAssertThrowsErrorAsync(
                try await database.apply(
                    space: fixture.space,
                    author: fixture.author,
                    expectedRevision: 0,
                    requestID: UUID(),
                    wireRevision: try fixture.tid(0),
                    writes: [
                        .put(uri: fixture.first, value: value, cid: cid),
                    ]
                )
            ) { error in
                guard case .malformed = error as? SwanError else {
                    return XCTFail(
                        "invalid record must fail as malformed input"
                    )
                }
            }
            let snapshot = try await database.repositorySnapshot(
                space: fixture.space,
                author: fixture.author
            )
            let pending = try await database.pendingOutbox()
            XCTAssertNil(snapshot)
            XCTAssertTrue(pending.isEmpty)
        }

        var poisonedLtHash = LtHash()
        poisonedLtHash.add(
            element:
                "\(fixture.first.collection)/\(fixture.first.rkey)/\(nonCanonicalCID)"
        )
        let poisonedRecovery = VerifiedSpaceCARRecovery(
            wireRevision: try fixture.tid(0),
            records: [
                SpaceRecord(
                    uri: fixture.first,
                    value: fixture.firstValue,
                    cid: nonCanonicalCID,
                    revision: 1
                ),
            ],
            ltHash: poisonedLtHash.serialized,
            commitment: poisonedLtHash.commitment
        )
        await XCTAssertThrowsErrorAsync(
            try await database.restorePortableRepositories([
                SQLitePortableRestoreRepository(
                    space: fixture.space,
                    author: fixture.author,
                    recovery: poisonedRecovery
                ),
            ])
        )
        let snapshot = try await database.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        let pending = try await database.pendingOutbox()
        XCTAssertNil(snapshot)
        XCTAssertTrue(pending.isEmpty)
    }

    func testOutboxWorkerDeliversOnceWithOpaquePayloadOutsideSQLiteTransaction() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        try await withClosedAccountDatabase(database) { database in
            let committed = try await fixture.commitFirst(on: database)
            let transport = RecordingOutboxTransport(database: database)
            let worker = PermissionedSpaceOutboxDeliveryWorker(
                database: database,
                transport: transport,
                configuration: try outboxConfiguration()
            )
            let now = Date(timeIntervalSinceNow: 60)

            let result = try await worker.deliverNext(now: now)
            XCTAssertEqual(result, .delivered(eventID: committed.outbox.id))
            let pending = try await database.pendingOutbox()
            let followUp = try await worker.deliverNext(now: now)
            XCTAssertEqual(pending, [])
            XCTAssertEqual(followUp, .idle)

            let delivered = await transport.notifications()
            XCTAssertEqual(delivered.count, 1)
            XCTAssertEqual(delivered.first?.id, committed.outbox.id)
            XCTAssertEqual(delivered.first?.payload, Data(committed.outbox.id.uuidString.lowercased().utf8))
            XCTAssertNil(delivered.first?.payload.range(of: fixture.firstValue))
            XCTAssertNil(delivered.first?.payload.range(of: Data(fixture.firstCID.utf8)))
            let transactionStates = await transport.observedWriteTransactions()
            XCTAssertEqual(transactionStates, [false])
        }
    }

    func testOutboxWorkerFailureIncrementsAttemptsAndUsesBoundedRetryDeadline() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        try await withClosedAccountDatabase(database) { database in
            let committed = try await fixture.commitFirst(on: database)
            let transport = RecordingOutboxTransport(database: database, failuresRemaining: 1)
            let configuration = try outboxConfiguration(
                initialFailureBackoff: 3,
                maximumFailureBackoff: 4
            )
            let worker = PermissionedSpaceOutboxDeliveryWorker(
                database: database,
                transport: transport,
                configuration: configuration
            )
            let now = Date(timeIntervalSinceNow: 60)

            let firstResult = try await worker.deliverNext(now: now)
            let pending = try await database.pendingOutbox()
            let beforeRetry = try await worker.deliverNext(now: now.addingTimeInterval(2.9))
            let retryResult = try await worker.deliverNext(now: now.addingTimeInterval(3))
            let deliveredIDs = (await transport.notifications()).map(\.id)
            let transactionStates = await transport.observedWriteTransactions()
            XCTAssertEqual(firstResult, .failed(eventID: committed.outbox.id, attempts: 1))
            XCTAssertEqual(pending.first?.attempts, 1)
            XCTAssertEqual(beforeRetry, .idle)
            XCTAssertEqual(retryResult, .delivered(eventID: committed.outbox.id))
            XCTAssertEqual(deliveredIDs, [committed.outbox.id, committed.outbox.id])
            XCTAssertEqual(transactionStates, [false, false])
        }
    }

    func testOutboxWorkerFailsClosedBeforeMaximumAttemptArithmetic() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        let committed = try await fixture.commitFirst(on: database)
        try await database.close()

        let databasePath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        ).path
        let rawConnection = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await rawConnection.query(
            "UPDATE permissioned_space_outbox SET attempts = ? WHERE id = ?",
            [.integer(Int.max), .text(committed.outbox.id.uuidString)]
        )
        try await rawConnection.close()

        let reopened = try await fixture.open()
        try await withClosedAccountDatabase(reopened) { reopened in
            let transport = RecordingOutboxTransport(database: reopened, failuresRemaining: 1)
            let worker = PermissionedSpaceOutboxDeliveryWorker(
                database: reopened,
                transport: transport,
                configuration: try outboxConfiguration()
            )

            await XCTAssertThrowsErrorAsync(
                try await worker.deliverNext(now: Date(timeIntervalSinceNow: 60))
            ) { error in
                XCTAssertEqual(
                    error as? SQLiteRepositoryError,
                    .corruptDatabase("outbox attempts overflow")
                )
            }
            let delivered = await transport.notifications()
            XCTAssertEqual(delivered, [])
        }
    }

    func testExpiredLeaseIsRecoveredAfterDatabaseRestartAndStaleTokenCannotAcknowledge() async throws {
        let fixture = try Fixture()
        var database: SQLiteAccountDatabase? = try await fixture.open()
        let committed = try await fixture.commitFirst(on: database!)
        let now = Date(timeIntervalSinceNow: 60)
        let maybeFirstLease = try await database!.leaseNextOutbox(
            now: now,
            leaseDuration: 2
        )
        let firstLease = try XCTUnwrap(maybeFirstLease)
        try await database!.close()
        database = nil

        let reopened = try await fixture.open()
        try await withClosedAccountDatabase(reopened) { reopened in
            let beforeExpiry = try await reopened.leaseNextOutbox(
                now: now.addingTimeInterval(1),
                leaseDuration: 2
            )
            let maybeRecovered = try await reopened.leaseNextOutbox(
                now: now.addingTimeInterval(3),
                leaseDuration: 2
            )
            XCTAssertNil(beforeExpiry)
            let recovered = try XCTUnwrap(maybeRecovered)
            XCTAssertEqual(recovered.event.id, committed.outbox.id)
            XCTAssertNotEqual(recovered.token, firstLease.token)
            let staleCompletion = try await reopened.completeOutboxLease(
                eventID: committed.outbox.id,
                token: firstLease.token
            )
            let recoveredCompletion = try await reopened.completeOutboxLease(
                eventID: committed.outbox.id,
                token: recovered.token
            )
            let pending = try await reopened.pendingOutbox()
            XCTAssertFalse(staleCompletion)
            XCTAssertTrue(recoveredCompletion)
            XCTAssertEqual(pending, [])
        }
    }

    func testOutboxLeaseMigrationUpgradesVersionOneRowsWithoutExposingPayload() async throws {
        let fixture = try Fixture()
        let databaseURL = SQLiteLayout.accountDatabase(in: fixture.root, did: fixture.author)
        try FileManager.default.createDirectory(
            at: databaseURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let eventID = UUID(uuidString: "20000000-0000-0000-0000-000000000099")!
        let createdAt = Int(Date().timeIntervalSince1970 * 1_000_000)
        let raw = try await SQLiteConnection.open(storage: .file(path: databaseURL.path))
        _ = try await raw.query(
            """
            CREATE TABLE permissioned_repository_migrations (
                version INTEGER PRIMARY KEY CHECK(version > 0),
                applied_at INTEGER NOT NULL CHECK(applied_at >= 0)
            )
            """
        )
        _ = try await raw.query(
            """
            CREATE TABLE permissioned_space_outbox (
                id TEXT PRIMARY KEY,
                space_uri TEXT NOT NULL,
                author_did TEXT NOT NULL,
                revision INTEGER NOT NULL,
                payload BLOB NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            )
            """
        )
        _ = try await raw.query(
            "INSERT INTO permissioned_repository_migrations(version, applied_at) VALUES (1, ?)",
            [.integer(createdAt)]
        )
        _ = try await raw.query(
            """
            INSERT INTO permissioned_space_outbox(
                id, space_uri, author_did, revision, payload, attempts, created_at
            ) VALUES (?, ?, ?, 1, ?, 0, ?)
            """,
            [
                .text(eventID.uuidString), .text(fixture.space.rawValue),
                .text(fixture.author),
                Data(eventID.uuidString.lowercased().utf8).sqliteData!,
                .integer(createdAt),
            ]
        )
        try await raw.close()
        try lockDownLegacySQLiteDatabase(databaseURL, dataDirectory: fixture.root)

        let migrated = try await fixture.open()
        try await withClosedAccountDatabase(migrated) { migrated in
            let pending = try await migrated.pendingOutbox()
            XCTAssertEqual(pending.map(\.id), [eventID])
            XCTAssertEqual(pending.first?.payload, Data(eventID.uuidString.lowercased().utf8))
            XCTAssertNil(pending.first?.payload.range(of: fixture.firstValue))
            let lease = try await migrated.leaseNextOutbox(
                now: Date(timeIntervalSince1970: Double(createdAt) / 1_000_000 + 1),
                leaseDuration: 5
            )
            XCTAssertEqual(lease?.event.id, eventID)
        }
    }

    func testConcurrentWorkersHaveOneActiveLeaseAndAtLeastOnceIdempotencyKey() async throws {
        let fixture = try Fixture()
        let firstDatabase = try await fixture.open()
        let secondDatabase = try await fixture.open()
        try await withClosedAccountDatabases(firstDatabase, secondDatabase) {
            firstDatabase, secondDatabase in
            let committed = try await fixture.commitFirst(on: firstDatabase)
            let barrier = OutboxDeliveryBarrier()
            let firstTransport = BlockingOutboxTransport(barrier: barrier)
            let firstWorker = PermissionedSpaceOutboxDeliveryWorker(
                database: firstDatabase,
                transport: firstTransport,
                configuration: try outboxConfiguration()
            )
            let secondTransport = RecordingOutboxTransport(database: secondDatabase)
            let secondWorker = PermissionedSpaceOutboxDeliveryWorker(
                database: secondDatabase,
                transport: secondTransport,
                configuration: try outboxConfiguration()
            )
            let now = Date(timeIntervalSinceNow: 60)

            let firstTask = Task { try await firstWorker.deliverNext(now: now) }
            await barrier.waitUntilStarted()
            let secondResult = try await secondWorker.deliverNext(now: now)
            let secondNotifications = await secondTransport.notifications()
            await barrier.release()
            let firstResult = try await firstTask.value
            let firstNotifications = (await firstTransport.notifications()).map(\.id)
            let pending = try await firstDatabase.pendingOutbox()
            XCTAssertEqual(secondResult, .idle)
            XCTAssertEqual(secondNotifications, [])
            XCTAssertEqual(firstResult, .delivered(eventID: committed.outbox.id))
            XCTAssertEqual(firstNotifications, [committed.outbox.id])
            XCTAssertEqual(pending, [])
        }
    }

    func testRepositoryStateMarkerRejectsTamperedReaderEnvelopeAfterReopen() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        _ = try await fixture.commitFirst(on: database)
        try await database.close()

        let readerSpecificBytes = Data(
            "ikm=reader-secret&contextSignature=signature&contentBinding=binding".utf8
        )
        let databasePath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        ).path
        let rawConnection = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await rawConnection.query(
            """
            UPDATE permissioned_repository_state
            SET current_commit = ?
            WHERE space_uri = ? AND author_did = ?
            """,
            [
                readerSpecificBytes.sqliteData!,
                .text(fixture.space.rawValue),
                .text(fixture.author),
            ]
        )
        try await rawConnection.close()

        let reopened = try await fixture.open()
        defer { Task { try? await reopened.close() } }
        await XCTAssertThrowsErrorAsync(
            try await reopened.repositorySnapshot(
                space: fixture.space,
                author: fixture.author
            )
        ) { error in
            XCTAssertEqual(
                error as? SQLiteRepositoryError,
                .corruptDatabase("invalid deterministic repository state marker")
            )
        }
        await XCTAssertThrowsErrorAsync(
            try await reopened.spaceRecord(fixture.first)
        )
    }

    func testFullCARPreparationRejectsCorruptCIDValueAndRepositoryStateBeforeSpooling() async throws {
        let fixture = try Fixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        let validCID = CID.fromDAGCBOR(fixture.firstValue).string
        _ = try await database.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try fixture.tid(0),
            writes: [.put(uri: fixture.first, value: fixture.firstValue, cid: validCID)]
        )
        let prepared = try await database.prepareRepositoryCARSnapshot(
            space: fixture.space,
            author: fixture.author
        )
        XCTAssertNotNil(prepared)
        prepared?.spool.cleanup()
        try await database.close()

        let databasePath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        ).path
        let wrongCID = CID.fromDAGCBOR(fixture.secondValue).string
        let rawCID = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await rawCID.query(
            "UPDATE permissioned_space_records SET cid = ? WHERE space_uri = ? AND author_did = ?",
            [.text(wrongCID), .text(fixture.space.rawValue), .text(fixture.author)]
        )
        try await rawCID.close()

        let cidCorrupt = try await fixture.open()
        await XCTAssertThrowsErrorAsync(
            try await cidCorrupt.prepareRepositoryCARSnapshot(
                space: fixture.space,
                author: fixture.author
            )
        ) { error in
            XCTAssertEqual(
                error as? SQLiteRepositoryError,
                .corruptDatabase("permissioned CAR snapshot does not match repository state")
            )
        }
        try await cidCorrupt.close()

        let rawState = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await rawState.query(
            "UPDATE permissioned_space_records SET cid = ? WHERE space_uri = ? AND author_did = ?",
            [.text(validCID), .text(fixture.space.rawValue), .text(fixture.author)]
        )
        _ = try await rawState.query(
            "UPDATE permissioned_repository_state SET current_commit = ? WHERE space_uri = ? AND author_did = ?",
            [
                Data("reader-specific-IKM-must-not-persist".utf8).sqliteData!,
                .text(fixture.space.rawValue), .text(fixture.author),
            ]
        )
        try await rawState.close()

        let stateCorrupt = try await fixture.open()
        await XCTAssertThrowsErrorAsync(
            try await stateCorrupt.prepareRepositoryCARSnapshot(
                space: fixture.space,
                author: fixture.author
            )
        ) { error in
            XCTAssertEqual(
                error as? SQLiteRepositoryError,
                .corruptDatabase("invalid deterministic repository state marker")
            )
        }
        try await stateCorrupt.close()
    }

    func testOutboxRejectsTamperedPayloadAfterReopen() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        let committed = try await fixture.commitFirst(on: database)
        try await database.close()

        let readerSpecificPayload = Data(
            "private-record-bytes-and-cid-must-not-be-a-notification".utf8
        )
        let databasePath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        ).path
        let rawConnection = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await rawConnection.query(
            "UPDATE permissioned_space_outbox SET payload = ? WHERE id = ?",
            [readerSpecificPayload.sqliteData!, .text(committed.outbox.id.uuidString)]
        )
        try await rawConnection.close()

        let reopened = try await fixture.open()
        do {
            _ = try await reopened.pendingOutbox()
            XCTFail("tampered outbox payload must fail closed")
        } catch {
            XCTAssertEqual(
                error as? SQLiteRepositoryError,
                .corruptDatabase("invalid opaque notification payload")
            )
        }
        try await reopened.close()
    }

    func testPendingOutboxRejectsMalformedLeasePairAfterReopen() async throws {
        let fixture = try Fixture()
        let databaseURL = SQLiteLayout.accountDatabase(in: fixture.root, did: fixture.author)
        try FileManager.default.createDirectory(
            at: databaseURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let eventID = UUID(uuidString: "20000000-0000-0000-0000-000000000098")!
        let timestamp = Int(Date().timeIntervalSince1970 * 1_000_000)
        let rawConnection = try await SQLiteConnection.open(storage: .file(path: databaseURL.path))
        do {
            _ = try await rawConnection.query(
                """
                CREATE TABLE permissioned_repository_migrations (
                    version INTEGER PRIMARY KEY CHECK(version > 0),
                    applied_at INTEGER NOT NULL CHECK(applied_at >= 0)
                )
                """
            )
            _ = try await rawConnection.query(
                """
                CREATE TABLE permissioned_space_outbox (
                    id TEXT PRIMARY KEY,
                    space_uri TEXT NOT NULL,
                    author_did TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    payload BLOB NOT NULL,
                    attempts INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
            _ = try await rawConnection.query(
                "INSERT INTO permissioned_repository_migrations(version, applied_at) VALUES (1, ?)",
                [.integer(timestamp)]
            )
            _ = try await rawConnection.query(
                """
                INSERT INTO permissioned_space_outbox(
                    id, space_uri, author_did, revision, payload, attempts, created_at
                ) VALUES (?, ?, ?, 1, ?, 0, ?)
                """,
                [
                    .text(eventID.uuidString), .text(fixture.space.rawValue),
                    .text(fixture.author),
                    Data(eventID.uuidString.lowercased().utf8).sqliteData!,
                    .integer(timestamp),
                ]
            )
            try await rawConnection.close()
        } catch {
            try? await rawConnection.close()
            throw error
        }
        try lockDownLegacySQLiteDatabase(databaseURL, dataDirectory: fixture.root)

        // This is the actual upgrade sequence for an old table: the additive
        // migration adds columns but SQLite cannot retroactively add the new
        // lease-pair CHECK constraint. A later corrupted legacy row must still
        // be rejected by `pendingOutbox`'s decoder.
        let upgraded = try await fixture.open()
        try await upgraded.close()
        let corruptingConnection = try await SQLiteConnection.open(
            storage: .file(path: databaseURL.path)
        )
        do {
            _ = try await corruptingConnection.query(
                "UPDATE permissioned_space_outbox SET lease_token = ?, lease_expires_at = NULL WHERE id = ?",
                [.text(UUID().uuidString), .text(eventID.uuidString)]
            )
            try await corruptingConnection.close()
        } catch {
            try? await corruptingConnection.close()
            throw error
        }

        let reopened = try await fixture.open()
        do {
            _ = try await reopened.pendingOutbox()
            XCTFail("malformed outbox lease must fail closed")
        } catch {
            XCTAssertEqual(
                error as? SQLiteRepositoryError,
                .corruptDatabase("invalid outbox lease")
            )
        }
        try await reopened.close()
    }

    func testPermissionedStorageMigrationUpgradesLegacyRowsBeforeRecordingSentinel() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        let committed = try await fixture.commitFirst(on: database)
        try await database.close()

        let legacyCommit = Data(
            "ikm=legacy-reader-secret&contextSignature=legacy-signature".utf8
        )
        let legacyPayload = Data(
            "legacy-private-record-bytes-and-cid".utf8
        )
        let databasePath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        ).path
        let rawConnection = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await rawConnection.query(
            "DELETE FROM permissioned_repository_migrations WHERE version = 1"
        )
        _ = try await rawConnection.query(
            """
            UPDATE permissioned_repository_state
            SET current_commit = ?
            WHERE space_uri = ? AND author_did = ?
            """,
            [
                legacyCommit.sqliteData!, .text(fixture.space.rawValue),
                .text(fixture.author),
            ]
        )
        _ = try await rawConnection.query(
            "UPDATE permissioned_space_outbox SET payload = ? WHERE id = ?",
            [legacyPayload.sqliteData!, .text(committed.outbox.id.uuidString)]
        )
        try await rawConnection.close()

        let migrated = try await fixture.open()
        let migratedSnapshot = try await migrated.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        let snapshot = try XCTUnwrap(migratedSnapshot)
        XCTAssertNotEqual(snapshot.state.commit, legacyCommit)
        XCTAssertEqual(snapshot.records.map(\.value), [fixture.firstValue])
        let pending = try await migrated.pendingOutbox()
        XCTAssertEqual(
            pending,
            [
                PersistedOutboxEvent(
                    id: committed.outbox.id,
                    space: fixture.space,
                    author: fixture.author,
                    revision: 1,
                    payload: Data(committed.outbox.id.uuidString.lowercased().utf8),
                    attempts: 0
                ),
            ]
        )
        try await migrated.close()

        let inspected = try await SQLiteConnection.open(storage: .file(path: databasePath))
        let sentinelRows = try await inspected.query(
            "SELECT version FROM permissioned_repository_migrations WHERE version = 1"
        )
        XCTAssertEqual(sentinelRows.count, 1)
        XCTAssertEqual(sentinelRows.first?.column("version")?.integer, 1)
        try await inspected.close()
    }

    func testPermissionedStorageMigrationPreservesForeignAuthoritySharedSpace() async throws {
        let fixture = try Fixture()
        let sharedSpace = try SpaceURI(
            authority: "did:plc:bob",
            spaceType: "app.bsky.bookmarks",
            skey: "shared"
        )
        let sharedRecord = try SpaceRecordURI(
            space: sharedSpace,
            author: fixture.author,
            collection: "app.bsky.feed.post",
            rkey: "shared-first"
        )
        let database = try await fixture.open()
        let committed = try await database.apply(
            space: sharedSpace,
            author: fixture.author,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try fixture.tid(0),
            writes: [
                .put(
                    uri: sharedRecord,
                    value: fixture.firstValue,
                    cid: fixture.firstCID
                ),
            ]
        )
        try await database.close()

        let databasePath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        ).path
        let rawConnection = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await rawConnection.query(
            "DELETE FROM permissioned_repository_migrations WHERE version = 1"
        )
        _ = try await rawConnection.query(
            """
            UPDATE permissioned_repository_state
            SET current_commit = ?
            WHERE space_uri = ? AND author_did = ?
            """,
            [
                Data("legacy-shared-space-commit".utf8).sqliteData!,
                .text(sharedSpace.rawValue),
                .text(fixture.author),
            ]
        )
        _ = try await rawConnection.query(
            "UPDATE permissioned_space_outbox SET payload = ? WHERE id = ?",
            [
                Data("legacy-shared-space-payload".utf8).sqliteData!,
                .text(committed.outbox.id.uuidString),
            ]
        )
        try await rawConnection.close()

        let migrated = try await fixture.open()
        let migratedSnapshot = try await migrated.repositorySnapshot(
            space: sharedSpace,
            author: fixture.author
        )
        let snapshot = try XCTUnwrap(migratedSnapshot)
        XCTAssertEqual(snapshot.state.revision, 1)
        XCTAssertEqual(snapshot.records.map(\.uri), [sharedRecord])
        let pending = try await migrated.pendingOutbox()
        XCTAssertEqual(pending.first?.space, sharedSpace)
        XCTAssertEqual(pending.first?.author, fixture.author)
        XCTAssertEqual(
            pending.first?.payload,
            Data(committed.outbox.id.uuidString.lowercased().utf8)
        )
        let next = try await migrated.apply(
            space: sharedSpace,
            author: fixture.author,
            expectedRevision: 1,
            requestID: UUID(),
            wireRevision: try fixture.tid(1),
            writes: [
                .put(
                    uri: sharedRecord,
                    value: fixture.secondValue,
                    cid: fixture.secondCID
                ),
            ]
        )
        XCTAssertEqual(next.state.revision, 2)
        try await migrated.close()
    }

    func testPermissionedStorageMigrationRollsBackWithoutSentinelForMalformedLegacyRows() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        let committed = try await fixture.commitFirst(on: database)
        try await database.close()

        let legacyCommit = Data("legacy-raw-commit".utf8)
        let databasePath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        ).path
        let rawConnection = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await rawConnection.query(
            "DELETE FROM permissioned_repository_migrations WHERE version = 1"
        )
        _ = try await rawConnection.query(
            """
            UPDATE permissioned_repository_state
            SET current_commit = ?
            WHERE space_uri = ? AND author_did = ?
            """,
            [
                legacyCommit.sqliteData!, .text(fixture.space.rawValue),
                .text(fixture.author),
            ]
        )
        _ = try await rawConnection.query(
            "UPDATE permissioned_space_outbox SET id = ? WHERE id = ?",
            [.text("not-a-uuid"), .text(committed.outbox.id.uuidString)]
        )
        try await rawConnection.close()

        await XCTAssertThrowsErrorAsync(
            try await fixture.open()
        ) { error in
            XCTAssertEqual(
                error as? SQLiteRepositoryError,
                .corruptDatabase("invalid outbox id")
            )
        }

        let inspected = try await SQLiteConnection.open(storage: .file(path: databasePath))
        let stateRows = try await inspected.query(
            """
            SELECT current_commit
            FROM permissioned_repository_state
            WHERE space_uri = ? AND author_did = ?
            """,
            [.text(fixture.space.rawValue), .text(fixture.author)]
        )
        let stateRow = try XCTUnwrap(stateRows.first)
        let currentCommit = try XCTUnwrap(
            Data(sqliteData: try XCTUnwrap(stateRow.column("current_commit")))
        )
        XCTAssertEqual(currentCommit, legacyCommit)
        let sentinelRows = try await inspected.query(
            "SELECT version FROM permissioned_repository_migrations WHERE version = 1"
        )
        XCTAssertTrue(sentinelRows.isEmpty)
        try await inspected.close()
    }

    func testPermissionedStorageMigrationRejectsCrossAccountLegacyStateRow() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        _ = try await fixture.commitFirst(on: database)
        try await database.close()

        let databasePath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        ).path
        let rawConnection = try await SQLiteConnection.open(storage: .file(path: databasePath))
        _ = try await rawConnection.query(
            "DELETE FROM permissioned_repository_migrations WHERE version = 1"
        )
        _ = try await rawConnection.query(
            """
            UPDATE permissioned_repository_state
            SET author_did = ?
            WHERE space_uri = ? AND author_did = ?
            """,
            [
                .text("did:plc:mallory"), .text(fixture.space.rawValue),
                .text(fixture.author),
            ]
        )
        try await rawConnection.close()

        await XCTAssertThrowsErrorAsync(
            try await fixture.open()
        ) { error in
            XCTAssertEqual(
                error as? SQLiteRepositoryError,
                .corruptDatabase("invalid permissioned repository state ownership")
            )
        }

        let inspected = try await SQLiteConnection.open(storage: .file(path: databasePath))
        let sentinelRows = try await inspected.query(
            "SELECT version FROM permissioned_repository_migrations WHERE version = 1"
        )
        XCTAssertTrue(sentinelRows.isEmpty)
        try await inspected.close()
    }

    func testCASFailureAndInvalidBatchRollBackEveryFact() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }

        _ = try await fixture.commitFirst(on: database)

        await XCTAssertThrowsErrorAsync(
            try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try fixture.tid(1),
                writes: [.put(uri: fixture.second, value: fixture.secondValue, cid: fixture.secondCID)],
            )
        ) { error in
            XCTAssertEqual(error as? SwanError, .conflict(expected: 0, actual: 1))
        }

        await XCTAssertThrowsErrorAsync(
            try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 1,
                requestID: UUID(),
                wireRevision: try fixture.tid(1),
                writes: [
                    .put(uri: fixture.second, value: fixture.secondValue, cid: fixture.secondCID),
                    .delete(uri: fixture.missing),
                ],
            )
        )

        let loadedSnapshot = try await database.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        let snapshot = try XCTUnwrap(loadedSnapshot)
        XCTAssertEqual(snapshot.state.revision, 1)
        XCTAssertEqual(snapshot.records.map(\.uri), [fixture.first])
        let secondRecord = try await database.spaceRecord(fixture.second)
        XCTAssertNil(secondRecord)

        guard case let .incremental(entries) = try await database.spaceOplog(
            space: fixture.space,
            author: fixture.author,
            since: 0
        ) else {
            return XCTFail("unexpected retention gap")
        }
        XCTAssertEqual(entries.count, 1)
        let pending = try await database.pendingOutbox()
        XCTAssertEqual(pending.count, 1)
    }

    func testDuplicateRequestIDCannotCreateASecondCommit() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        let requestID = UUID(uuidString: "10000000-0000-0000-0000-000000000099")!

        _ = try await database.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 0,
            requestID: requestID,
            wireRevision: try fixture.tid(0),
            writes: [.put(uri: fixture.first, value: fixture.firstValue, cid: fixture.firstCID)],
        )

        await XCTAssertThrowsErrorAsync(
            try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 1,
                requestID: requestID,
                wireRevision: try fixture.tid(1),
                writes: [.put(uri: fixture.second, value: fixture.secondValue, cid: fixture.secondCID)],
            )
        ) { error in
            XCTAssertEqual(error as? SQLiteRepositoryError, .duplicateRequest(requestID))
        }

        let loadedSnapshot = try await database.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        let snapshot = try XCTUnwrap(loadedSnapshot)
        XCTAssertEqual(snapshot.state.revision, 1)
        XCTAssertEqual(snapshot.records.map(\.uri), [fixture.first])
        let pending = try await database.pendingOutbox()
        XCTAssertEqual(pending.count, 1)
    }

    func testSeparateConnectionsRaceThroughSQLiteCAS() async throws {
        let fixture = try Fixture()
        let firstDatabase = try await fixture.open()
        let secondDatabase = try await fixture.open()
        defer {
            Task {
                try? await firstDatabase.close()
                try? await secondDatabase.close()
            }
        }

        let outcomes = await withTaskGroup(
            of: Result<PersistedRepositoryCommit, any Error>.self,
            returning: [Result<PersistedRepositoryCommit, any Error>].self
        ) { group in
            group.addTask {
                do {
                    return .success(
                        try await firstDatabase.apply(
                            space: fixture.space,
                            author: fixture.author,
                            expectedRevision: 0,
                            requestID: UUID(),
                            wireRevision: try fixture.tid(0),
                            writes: [
                                .put(
                                    uri: fixture.first,
                                    value: fixture.firstValue,
                                    cid: fixture.firstCID
                                )
                            ],
                        )
                    )
                } catch {
                    return .failure(error)
                }
            }
            group.addTask {
                do {
                    return .success(
                        try await secondDatabase.apply(
                            space: fixture.space,
                            author: fixture.author,
                            expectedRevision: 0,
                            requestID: UUID(),
                            wireRevision: try fixture.tid(0),
                            writes: [
                                .put(
                                    uri: fixture.second,
                                    value: fixture.secondValue,
                                    cid: fixture.secondCID
                                )
                            ],
                        )
                    )
                } catch {
                    return .failure(error)
                }
            }
            return await group.reduce(into: []) { $0.append($1) }
        }

        let successes = outcomes.compactMap { try? $0.get() }
        let failures = outcomes.compactMap { result -> (any Error)? in
            guard case let .failure(error) = result else { return nil }
            return error
        }
        XCTAssertEqual(successes.count, 1)
        XCTAssertEqual(failures.count, 1)
        XCTAssertEqual(
            failures.first as? SwanError,
            .conflict(expected: 0, actual: 1)
        )

        let loadedSnapshot = try await firstDatabase.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        let snapshot = try XCTUnwrap(loadedSnapshot)
        XCTAssertEqual(snapshot.state.revision, 1)
        XCTAssertEqual(snapshot.records.count, 1)
        let pending = try await firstDatabase.pendingOutbox()
        XCTAssertEqual(pending.count, 1)
    }

    func testSameInstanceGateHidesRolledBackOutboxAndPreventsNestedTransaction() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        let barrier = FailingApplyBarrier()
        await database.installTestingHooks(
            SQLiteTestingHooks(beforeApplyCommit: { try await barrier.pauseThenFailOnce() })
        )
        defer { Task { try? await database.close() } }

        let failingApply = Task {
            try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try fixture.tid(0),
                writes: [
                    .put(uri: fixture.first, value: fixture.firstValue, cid: fixture.firstCID)
                ],
            )
        }
        await barrier.waitUntilPaused()

        let pollStarted = AsyncSignal()
        let pendingPoll = Task {
            await pollStarted.signal()
            return try await database.pendingOutbox()
        }
        await pollStarted.wait()
        for _ in 0..<20 { await Task.yield() }

        let succeedingApply = Task {
            try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try fixture.tid(1),
                writes: [
                    .put(uri: fixture.second, value: fixture.secondValue, cid: fixture.secondCID)
                ],
            )
        }

        await barrier.release()
        do {
            _ = try await failingApply.value
            XCTFail("the injected transaction failure should roll back")
        } catch {
            XCTAssertTrue(error is InjectedTransactionFailure)
        }

        let eventsDuringFailure = try await pendingPoll.value
        XCTAssertEqual(eventsDuringFailure, [])
        let committed = try await succeedingApply.value
        XCTAssertEqual(committed.state.revision, 1)
        let finalPending = try await database.pendingOutbox()
        XCTAssertEqual(finalPending.count, 1)
    }

    func testSnapshotUsesOneStableSQLiteReadTransaction() async throws {
        let fixture = try Fixture()
        let reader = try await fixture.open()
        let writer = try await fixture.open()
        defer {
            Task {
                try? await reader.close()
                try? await writer.close()
            }
        }
        _ = try await fixture.commitFirst(on: reader)

        let barrier = SnapshotReadBarrier()
        await reader.installTestingHooks(
            SQLiteTestingHooks(afterSnapshotStateRead: { await barrier.pause() })
        )
        let snapshotTask = Task {
            try await reader.repositorySnapshot(
                space: fixture.space,
                author: fixture.author
            )
        }
        await barrier.waitUntilPaused()

        _ = try await writer.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 1,
            requestID: UUID(),
            wireRevision: try fixture.tid(1),
            writes: [
                .put(uri: fixture.second, value: fixture.secondValue, cid: fixture.secondCID)
            ],
        )
        await barrier.release()

        let loadedSnapshot = try await snapshotTask.value
        let snapshot = try XCTUnwrap(loadedSnapshot)
        XCTAssertEqual(snapshot.state.revision, 1)
        XCTAssertEqual(snapshot.records.map(\.uri), [fixture.first])

        let current = try await reader.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        XCTAssertEqual(current?.state.revision, 2)
        XCTAssertEqual(current?.records.count, 2)
    }

    func testFullCARSpoolUsesOneStableSQLiteReadTransaction() async throws {
        let fixture = try Fixture()
        let reader = try await fixture.open()
        let writer = try await fixture.open()
        defer {
            Task {
                try? await reader.close()
                try? await writer.close()
                try? FileManager.default.removeItem(at: fixture.root)
            }
        }
        let firstCID = CID.fromDAGCBOR(fixture.firstValue).string
        _ = try await reader.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try fixture.tid(0),
            writes: [.put(uri: fixture.first, value: fixture.firstValue, cid: firstCID)]
        )

        let barrier = SnapshotReadBarrier()
        await reader.installTestingHooks(
            SQLiteTestingHooks(afterSnapshotStateRead: { await barrier.pause() })
        )
        let snapshotTask = Task {
            try await reader.prepareRepositoryCARSnapshot(
                space: fixture.space,
                author: fixture.author
            )
        }
        await barrier.waitUntilPaused()

        let secondCID = CID.fromDAGCBOR(fixture.secondValue).string
        _ = try await writer.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 1,
            requestID: UUID(),
            wireRevision: try fixture.tid(1),
            writes: [.put(uri: fixture.second, value: fixture.secondValue, cid: secondCID)]
        )
        await barrier.release()

        let preparedResult = try await snapshotTask.value
        let prepared = try XCTUnwrap(preparedResult)
        let preparedWireRevision = try XCTUnwrap(prepared.state.wireRevision)
        XCTAssertEqual(preparedWireRevision, try fixture.tid(0).toString())
        XCTAssertEqual(prepared.state.commitment.count, 32)
        let key = P256.Signing.PrivateKey()
        let envelope = try SpaceCommitCodec.sign(
            context: try SpaceCommitContext(
                space: fixture.space,
                author: fixture.author,
                rev: preparedWireRevision,
                ikm: Data(repeating: 0x43, count: 32)
            ),
            commitment: prepared.state.commitment,
            key: key
        )
        var car = try SpaceCARCodec.recoveryPrefix(
            commit: envelope,
            indexCID: prepared.spool.indexCID
        )
        try await prepared.spool.streamBody { car.append($0) }
        let recovery = try SpaceCARCodec.verifyRecovery(
            car,
            space: fixture.space,
            author: fixture.author,
            publicKey: key.publicKey
        )
        XCTAssertEqual(recovery.wireRevision.toString(), try fixture.tid(0).toString())
        XCTAssertEqual(recovery.records.map { $0.uri }, [fixture.first])
        XCTAssertEqual(recovery.records.map { $0.cid }, [firstCID])
        XCTAssertEqual(recovery.commitment, prepared.state.commitment)
        XCTAssertTrue(prepared.spool.isCleanedUp)
    }

    func testOplogPreservesWireRevisionActionAndPreviousCID() async throws {
        let fixture = try Fixture()
        var database: SQLiteAccountDatabase? = try await fixture.open()
        let createRevision = try fixture.tid(0)
        let updateRevision = try fixture.tid(1)
        let deleteRevision = try fixture.tid(2)

        _ = try await database!.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: createRevision,
            writes: [
                .put(uri: fixture.first, value: fixture.firstValue, cid: fixture.firstCID)
            ],
        )
        _ = try await database!.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 1,
            requestID: UUID(),
            wireRevision: updateRevision,
            writes: [
                .put(uri: fixture.first, value: fixture.secondValue, cid: fixture.secondCID)
            ],
        )
        _ = try await database!.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 2,
            requestID: UUID(),
            wireRevision: deleteRevision,
            writes: [.delete(uri: fixture.first)],
        )

        try await database!.close()
        database = nil
        let reopened = try await fixture.open()
        defer { Task { try? await reopened.close() } }

        guard case let .incremental(entries) = try await reopened.spaceOplog(
            space: fixture.space,
            author: fixture.author,
            since: 0
        ) else {
            return XCTFail("all three commits should be retained")
        }
        XCTAssertEqual(entries.map(\.wireRevision), [
            createRevision, updateRevision, deleteRevision,
        ])
        XCTAssertEqual(entries.map(\.action), [.create, .update, .delete])
        XCTAssertEqual(entries.map(\.previousCID), [nil, fixture.firstCID, fixture.secondCID])
        XCTAssertEqual(entries.map(\.cid), [fixture.firstCID, fixture.secondCID, nil])
        let snapshot = try await reopened.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        XCTAssertEqual(snapshot?.state.wireRevision, deleteRevision)
    }

    func testAccountDIDRejectsCrossAccountPublicAndPermissionedFacts() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        let otherAuthor = "did:plc:bob"
        let otherRecord = try SpaceRecordURI(
            space: fixture.space,
            author: otherAuthor,
            collection: "app.bsky.feed.post",
            rkey: "other"
        )

        await XCTAssertThrowsErrorAsync(
            try await database.apply(
                space: fixture.space,
                author: otherAuthor,
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try fixture.tid(0),
                writes: [.put(uri: otherRecord, value: fixture.firstValue, cid: fixture.firstCID)],
            )
        ) { error in
            guard case .unauthorized = error as? SwanError else {
                return XCTFail("cross-account author must be unauthorized")
            }
        }

        let otherPublic = try PublicRecordURI(
            "at://did:plc:bob/app.bsky.feed.post/other"
        )
        await XCTAssertThrowsErrorAsync(
            try await database.putPublicRecord(
                uri: otherPublic,
                value: fixture.firstValue,
                cid: fixture.firstCID,
                revision: 1
            )
        ) { error in
            guard case .unauthorized = error as? SwanError else {
                return XCTFail("cross-account public record must be unauthorized")
            }
        }
        await XCTAssertThrowsErrorAsync(
            try await database.publicRecord(otherPublic)
        )
        await XCTAssertThrowsErrorAsync(
            try await database.repositorySnapshot(
                space: fixture.space,
                author: otherAuthor
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await database.spaceRecord(otherRecord)
        )

        XCTAssertThrowsError(
            try PublicRecordURI("at://not-a-did/app.bsky.feed.post/one")
        )
        XCTAssertThrowsError(
            try PublicRecordURI("at://did:plc:alice/not-an-nsid/one")
        )
        XCTAssertThrowsError(
            try PublicRecordURI("at://did:plc:alice/app.bsky.feed.post/bad/key")
        )
    }

    func testDurableBlobPayloadAndNamespaceReferencesSurviveRestart() async throws {
        let fixture = try Fixture()
        var database: SQLiteAccountDatabase? = try await fixture.open()
        let payload = Data([0x00, 0xff, 0x42, 0x01])
        let spaceReference = try await database!.putBlob(
            payload,
            namespace: .space(fixture.space)
        )
        let canonical = try CID.parse(spaceReference.cid)
        XCTAssertEqual(canonical.codec, .raw)
        XCTAssertEqual(canonical, CID.fromBlob(payload))
        let privateCASPath = SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        )
        .deletingLastPathComponent()
        .appending(path: "permissioned-blob-cas")
        .appending(path: Hex.encode(SHA256.hash(data: Data(fixture.author.utf8))))
        .appending(path: String(Hex.encode(canonical.multihash.digest).prefix(2)))
        .appending(path: "\(Hex.encode(canonical.multihash.digest)).blob")
        XCTAssertTrue(FileManager.default.fileExists(atPath: privateCASPath.path))
        let privateAsPublic = try await database!.publicBlobData(
            cid: spaceReference.cid
        )
        XCTAssertNil(privateAsPublic)
        try await database!.close()
        database = nil

        let reopened = try await fixture.open()
        defer { Task { try? await reopened.close() } }
        let blobStore: any BlobStore = reopened
        let reopenedPrivate = try await blobStore.data(for: spaceReference)
        XCTAssertEqual(reopenedPrivate, payload)
        let otherSpace = try SpaceURI(
            authority: fixture.author,
            spaceType: "app.bsky.bookmarks",
            skey: "other"
        )
        let wrongSpaceReference = BlobReference(
            cid: spaceReference.cid,
            namespace: .space(otherSpace)
        )
        await XCTAssertThrowsErrorAsync(
            try await blobStore.data(for: wrongSpaceReference)
        )

        let publicReference = try await blobStore.put(
            payload,
            namespace: .public
        )
        XCTAssertEqual(publicReference.cid, spaceReference.cid)
        let reopenedPublic = try await blobStore.publicData(
            cid: publicReference.cid
        )
        XCTAssertEqual(reopenedPublic, payload)

        try await blobStore.remove(publicReference)
        let removedPublic = try await blobStore.publicData(
            cid: publicReference.cid
        )
        XCTAssertNil(removedPublic)
        let retainedPrivate = try await blobStore.data(for: spaceReference)
        XCTAssertEqual(retainedPrivate, payload)

        // The physical CAS entry is shared across namespace references but
        // cannot be reclaimed while the permissioned reference remains.
        XCTAssertTrue(FileManager.default.fileExists(atPath: privateCASPath.path))
        try await blobStore.remove(spaceReference)
        XCTAssertFalse(FileManager.default.fileExists(atPath: privateCASPath.path))
    }

    func testPublicStreamingBlobUploadUsesBoundedCASAndPublicNamespaceOnly() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }

        let chunks = [
            Data(repeating: 0x11, count: 37 * 1_024),
            Data(repeating: 0x22, count: 53 * 1_024),
            Data(repeating: 0x33, count: 19 * 1_024),
        ]
        let expected = chunks.reduce(into: Data()) { $0.append($1) }
        let source: @Sendable (
            @escaping (Data) async throws -> Void
        ) async throws -> Void = { sink in
            for chunk in chunks {
                try await sink(chunk)
            }
        }

        let reference = try await database.putStreaming(
            namespace: .public,
            mimeType: "image/test",
            maximumBytes: 256 * 1_024 * 1_024,
            source: source
        )
        XCTAssertEqual(reference.cid, CID.fromBlob(expected).string)

        let maybePublicBlob = try await database.publicBlob(cid: reference.cid)
        let publicBlob = try XCTUnwrap(maybePublicBlob)
        XCTAssertEqual(publicBlob.mimeType, "image/test")
        XCTAssertEqual(publicBlob.body.contentLength, expected.count)
        let publicReachable = try await database.publicBlobExists(cid: reference.cid)
        XCTAssertTrue(publicReachable)
        var received = Data()
        var maximumChunk = 0
        try await publicBlob.body.streamBody(maximumChunkBytes: 8 * 1_024) { chunk in
            maximumChunk = max(maximumChunk, chunk.count)
            received.append(chunk)
        }
        XCTAssertEqual(received, expected)
        XCTAssertLessThanOrEqual(maximumChunk, 8 * 1_024)

        let privatePayload = Data(repeating: 0x7a, count: 17 * 1_024)
        let privateReference = try await database.putBlob(
            privatePayload,
            namespace: .space(fixture.space)
        )
        let privateBlob = try await database.publicBlob(cid: privateReference.cid)
        XCTAssertNil(privateBlob)
        let privateReachable = try await database.publicBlobExists(cid: privateReference.cid)
        XCTAssertFalse(privateReachable)

        let tooLargeSource: @Sendable (
            @escaping (Data) async throws -> Void
        ) async throws -> Void = { sink in
            try await sink(Data(repeating: 0x44, count: 6))
        }
        await XCTAssertThrowsErrorAsync(
            try await database.putStreaming(
                namespace: .public,
                mimeType: nil,
                maximumBytes: 5,
                source: tooLargeSource
            )
        ) { error in
            guard case .malformed = error as? SwanError else {
                return XCTFail("oversized streamed upload must be malformed")
            }
        }
    }

    func testAccountBlobQuotaDeduplicatesAndReleasesDurableCapacity() async throws {
        let fixture = try Fixture()
        let quota = AccountBlobQuota(maximumUniqueBytes: 10, maximumReferences: 3)
        let database = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root,
            did: fixture.author,
            blobQuota: quota
        )
        defer { Task { try? await database.close() } }

        let firstPayload = Data(repeating: 0x11, count: 6)
        let first = try await database.putBlob(firstPayload, namespace: .public)
        let duplicate = try await database.putBlob(firstPayload, namespace: .public)
        XCTAssertEqual(duplicate, first, "an exact reference must consume no additional quota")
        _ = try await database.putBlob(firstPayload, namespace: .space(fixture.space))

        let secondPayload = Data(repeating: 0x22, count: 4)
        let second = try await database.putBlob(secondPayload, namespace: .public)
        await XCTAssertThrowsErrorAsync(
            try await database.putBlob(Data([0x33]), namespace: .public)
        ) { error in
            XCTAssertEqual(error as? BlobQuotaError, .uniqueBytesExceeded(limit: 10))
        }

        try await database.removeBlobReference(second)
        let replacement = try await database.putBlob(
            Data(repeating: 0x44, count: 4),
            namespace: .public
        )
        XCTAssertNotEqual(replacement.cid, second.cid)

        let otherSpace = try SpaceURI(
            authority: fixture.author,
            spaceType: "app.bsky.bookmarks",
            skey: "quota-other"
        )
        await XCTAssertThrowsErrorAsync(
            try await database.putBlob(firstPayload, namespace: .space(otherSpace))
        ) { error in
            XCTAssertEqual(error as? BlobQuotaError, .referenceCountExceeded(limit: 3))
        }
    }

    func testConcurrentAccountBlobQuotaCannotOversubscribe() async throws {
        let fixture = try Fixture()
        let quota = AccountBlobQuota(maximumUniqueBytes: 16, maximumReferences: 16)
        var writers: [SQLiteAccountDatabase] = []
        for _ in 0 ..< 8 {
            writers.append(try await SQLiteAccountDatabase(
                dataDirectory: fixture.root,
                did: fixture.author,
                blobQuota: quota
            ))
        }
        defer {
            for writer in writers {
                Task { try? await writer.close() }
            }
        }

        let outcomes = await withTaskGroup(of: Bool.self, returning: [Bool].self) { group in
            for (index, writer) in writers.enumerated() {
                group.addTask {
                    do {
                        _ = try await writer.putBlob(
                            Data(repeating: UInt8(index + 1), count: 8),
                            namespace: .public
                        )
                        return true
                    } catch is BlobQuotaError {
                        return false
                    } catch {
                        XCTFail("unexpected concurrent quota error: \(error)")
                        return false
                    }
                }
            }
            return await group.reduce(into: []) { $0.append($1) }
        }
        XCTAssertEqual(outcomes.filter(\.self).count, 2)
    }

    func testAccountBlobQuotaIsIsolatedByAccountDatabase() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanBlobQuotaIsolation-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let quota = AccountBlobQuota(maximumUniqueBytes: 4, maximumReferences: 1)
        let alice = try await SQLiteAccountDatabase(
            dataDirectory: root, did: "did:plc:alice", blobQuota: quota
        )
        let bob = try await SQLiteAccountDatabase(
            dataDirectory: root, did: "did:plc:bob", blobQuota: quota
        )
        defer {
            Task { try? await alice.close() }
            Task { try? await bob.close() }
        }

        _ = try await alice.putBlob(Data(repeating: 0xa1, count: 4), namespace: .public)
        await XCTAssertThrowsErrorAsync(
            try await alice.putBlob(Data([0xa2]), namespace: .public)
        )
        _ = try await bob.putBlob(Data(repeating: 0xb1, count: 4), namespace: .public)
    }

    func testPrivateCASRefusesCorruptOrSymlinkedPayloadsAndReleasesCancelledStreams() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }

        _ = try await database.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try fixture.tid(0),
            writes: [.put(
                uri: fixture.first,
                value: fixture.firstValue,
                cid: fixture.firstCID
            )]
        )

        func casPath(_ cid: String) throws -> URL {
            let parsed = try CID.parse(cid)
            let digest = Hex.encode(parsed.multihash.digest)
            return SQLiteLayout.accountDatabase(in: fixture.root, did: fixture.author)
                .deletingLastPathComponent()
                .appending(path: "permissioned-blob-cas")
                .appending(path: Hex.encode(SHA256.hash(data: Data(fixture.author.utf8))))
                .appending(path: String(digest.prefix(2)))
                .appending(path: "\(digest).blob")
        }

        let firstPayload = Data(repeating: 0x31, count: 128 * 1_024)
        let first = try await database.putBlob(
            firstPayload,
            namespace: .space(fixture.space)
        )
        let firstPath = try casPath(first.cid)
        let maybeFirstBody = try await database.permissionedBlob(
            space: fixture.space, author: fixture.author, cid: first.cid
        )
        let firstBody = try XCTUnwrap(maybeFirstBody)
        var maximumChunk = 0
        enum ConsumerFailure: Error { case stop }
        await XCTAssertThrowsErrorAsync(
            try await firstBody.body.streamBody(maximumChunkBytes: 64 * 1_024) { chunk in
                maximumChunk = max(maximumChunk, chunk.count)
                throw ConsumerFailure.stop
            }
        )
        XCTAssertLessThanOrEqual(maximumChunk, 64 * 1_024)
        // The cancelled one-shot descriptor was closed, so a subsequent
        // authorized open succeeds instead of inheriting stale stream state.
        let maybeRetry = try await database.permissionedBlob(
            space: fixture.space, author: fixture.author, cid: first.cid
        )
        let retry = try XCTUnwrap(maybeRetry)
        var retryLength = 0
        try await retry.body.streamBody(maximumChunkBytes: 64 * 1_024) { chunk in
            retryLength += chunk.count
        }
        XCTAssertEqual(retryLength, firstPayload.count)

        let corruptHandle = try FileHandle(forWritingTo: firstPath)
        try corruptHandle.seek(toOffset: 0)
        try corruptHandle.write(contentsOf: Data(repeating: 0x99, count: 64 * 1_024))
        try corruptHandle.close()
        await XCTAssertThrowsErrorAsync(
            try await database.permissionedBlob(
                space: fixture.space, author: fixture.author, cid: first.cid
            )
        )

        let second = try await database.putBlob(
            Data("second private payload".utf8),
            namespace: .space(fixture.space)
        )
        let secondPath = try casPath(second.cid)
        try FileManager.default.removeItem(at: secondPath)
        try FileManager.default.createSymbolicLink(
            at: secondPath,
            withDestinationURL: firstPath
        )
        await XCTAssertThrowsErrorAsync(
            try await database.permissionedBlob(
                space: fixture.space, author: fixture.author, cid: second.cid
            )
        )
    }

    func testLegacySQLiteBlobMigratesPrivatelyAndNeverBecomesAnXRPCBlobCID() async throws {
        let fixture = try Fixture()
        var database: SQLiteAccountDatabase? = try await fixture.open()
        let payload = Data("legacy private blob".utf8)
        let legacyCID = "sha256:\(Hex.encode(SHA256.hash(data: payload)))"
        let reference = BlobReference(cid: legacyCID, namespace: .space(fixture.space))
        try await database!.close()
        database = nil

        let connection = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(
                in: fixture.root, did: fixture.author
            ).path)
        )
        _ = try await connection.query(
            """
            INSERT INTO blob_payloads(cid, payload, storage_kind, byte_count)
            VALUES (?, ?, 'legacy-sqlite', ?)
            """,
            [.text(legacyCID), payload.sqliteData!, .integer(payload.count)]
        )
        _ = try await connection.query(
            """
            INSERT INTO blob_namespace_references(cid, namespace_kind, space_uri)
            VALUES (?, 'space', ?)
            """,
            [.text(legacyCID), .text(fixture.space.rawValue)]
        )
        try await connection.close()

        database = try await fixture.open()
        let migrated = try await database!.blobData(for: reference)
        XCTAssertEqual(migrated, payload)
        // A compatibility read is allowed to stage a private CAS file, but
        // the legacy identifier remains unreachable from `getBlob`'s strict
        // raw-CID path even after that media migration.
        await XCTAssertThrowsErrorAsync(
            try await database!.permissionedBlob(
                space: fixture.space,
                author: fixture.author,
                cid: legacyCID
            )
        )
        try await database!.close()
        database = nil

        let reopened = try await fixture.open()
        defer { Task { try? await reopened.close() } }
        let reopenedPayload = try await reopened.blobData(for: reference)
        XCTAssertEqual(reopenedPayload, payload)
    }

    func testStreamLegacySQLiteBlobUsesBoundedSQLiteSlices() async throws {
        let fixture = try Fixture()
        var database: SQLiteAccountDatabase? = try await fixture.open()
        let payload = Data(
            repeating: 0x5a,
            count: (64 * 1_024 * 3) + 17
        )
        let legacyCID = "sha256:\(Hex.encode(SHA256.hash(data: payload)))"
        let reference = BlobReference(
            cid: legacyCID,
            namespace: .space(fixture.space)
        )
        try await database!.close()
        database = nil
        try await insertLegacyBlob(
            fixture: fixture,
            cid: legacyCID,
            payload: payload,
            byteCount: payload.count
        )

        let streamDatabase = try await fixture.open()
        defer { Task { try? await streamDatabase.close() } }
        let collector = LegacyBlobChunkCollector()
        try await streamDatabase.streamBlobData(
            for: reference,
            maximumBytes: payload.count
        ) { chunk in
            await collector.append(chunk)
        }

        let received = await collector.data
        let maximumChunk = await collector.maximumChunk
        XCTAssertEqual(received, payload)
        XCTAssertLessThanOrEqual(maximumChunk, 64 * 1_024)
        let connection = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(
                in: fixture.root, did: fixture.author
            ).path)
        )
        let rows = try await connection.query(
            "SELECT storage_kind FROM blob_payloads WHERE cid = ?",
            [.text(legacyCID)]
        )
        XCTAssertEqual(rows.first?.column("storage_kind")?.string, "legacy-sqlite")
        try await connection.close()
    }

    func testLegacyAndRawCIDAliasesProtectOnePhysicalCASAcrossRemovalAndRestart() async throws {
        let fixture = try Fixture()
        var database: SQLiteAccountDatabase? = try await fixture.open()
        let payload = Data("legacy and raw CID physical alias".utf8)
        let legacyCID = "sha256:\(Hex.encode(SHA256.hash(data: payload)))"
        let legacyReference = BlobReference(
            cid: legacyCID,
            namespace: .space(fixture.space)
        )
        try await database!.close()
        database = nil
        try await insertLegacyBlob(
            fixture: fixture,
            cid: legacyCID,
            payload: payload,
            byteCount: payload.count
        )

        database = try await fixture.open()
        let migratedLegacy = try await database!.blobData(for: legacyReference)
        XCTAssertEqual(migratedLegacy, payload)
        let rawReference = try await database!.putBlob(payload, namespace: .public)
        let rawCASPath = try privateCASPath(fixture: fixture, cid: rawReference.cid)
        XCTAssertTrue(FileManager.default.fileExists(atPath: rawCASPath.path))

        // Raw-first removal must leave the migrated legacy alias reachable.
        try await database!.removeBlobReference(rawReference)
        let legacyAfterRawRemoval = try await database!.blobData(for: legacyReference)
        XCTAssertEqual(legacyAfterRawRemoval, payload)
        XCTAssertTrue(FileManager.default.fileExists(atPath: rawCASPath.path))
        try await database!.close()
        database = nil

        database = try await fixture.open()
        let legacyAfterRestart = try await database!.blobData(for: legacyReference)
        XCTAssertEqual(legacyAfterRestart, payload)
        let rawAgain = try await database!.putBlob(payload, namespace: .public)

        // The reverse removal must retain the canonical raw survivor. The
        // restart path must not treat the old legacy CID's reclamation as an
        // authority to unlink the shared digest.
        try await database!.removeBlobReference(legacyReference)
        let rawAfterLegacyRemoval = try await database!.publicBlobData(cid: rawAgain.cid)
        XCTAssertEqual(rawAfterLegacyRemoval, payload)
        XCTAssertTrue(FileManager.default.fileExists(atPath: rawCASPath.path))
        try await database!.close()
        database = nil

        let reopened = try await fixture.open()
        defer { Task { try? await reopened.close() } }
        let reopenedRaw = try await reopened.publicBlobData(cid: rawAgain.cid)
        XCTAssertEqual(reopenedRaw, payload)
        XCTAssertTrue(FileManager.default.fileExists(atPath: rawCASPath.path))
        try await reopened.removeBlobReference(rawAgain)
        XCTAssertFalse(FileManager.default.fileExists(atPath: rawCASPath.path))
    }

    func testBlobLifecycleSerializesReReferenceAgainstLastRemovalAcrossConnections() async throws {
        let fixture = try Fixture()
        let remover = try await fixture.open()
        let writer = try await fixture.open()
        defer {
            Task {
                try? await writer.close()
                try? await remover.close()
            }
        }

        let payload = Data("same private bytes, new namespace".utf8)
        let original = try await remover.putBlob(
            payload,
            namespace: .space(fixture.space)
        )
        let barrier = BlobLifecycleBarrier()
        await writer.installTestingHooks(
            SQLiteTestingHooks(beforeBlobReferenceCommit: {
                try await barrier.pause()
            })
        )

        let reReference = Task {
            try await writer.putBlob(payload, namespace: .public)
        }
        await barrier.waitUntilPaused()

        let removalStarted = AsyncSignal()
        let removeLastReference = Task {
            await removalStarted.signal()
            try await remover.removeBlobReference(original)
        }
        await removalStarted.wait()
        for _ in 0 ..< 20 { await Task.yield() }

        // The writer has already opened/adopted the CAS but has not yet
        // committed its new reference.  Without the per-CID lifecycle lock,
        // the remover can now unlink the file and delete metadata, leaving
        // the writer to commit a reference to a missing path.
        await barrier.release()
        let publicReference = try await reReference.value
        try await removeLastReference.value

        XCTAssertEqual(publicReference.cid, original.cid)
        let retainedPublic = try await writer.publicBlobData(cid: original.cid)
        XCTAssertEqual(retainedPublic, payload)
        await XCTAssertThrowsErrorAsync(
            try await writer.blobData(for: original)
        )
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: try privateCASPath(fixture: fixture, cid: original.cid).path
            )
        )
    }

    func testRestartReconcilesCommittedCASReclamationIntent() async throws {
        let fixture = try Fixture()
        var database: SQLiteAccountDatabase? = try await fixture.open()
        let payload = Data("post-commit CAS reclamation".utf8)
        let reference = try await database!.putBlob(
            payload,
            namespace: .space(fixture.space)
        )
        let casPath = try privateCASPath(fixture: fixture, cid: reference.cid)
        await database!.installTestingHooks(
            SQLiteTestingHooks(afterBlobReclaimCommit: {
                throw InjectedTransactionFailure()
            })
        )

        await XCTAssertThrowsErrorAsync(
            try await database!.removeBlobReference(reference)
        ) { error in
            XCTAssertTrue(error is InjectedTransactionFailure)
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: casPath.path))
        let publicAfterReclaimIntent = try await database!.publicBlobData(cid: reference.cid)
        XCTAssertNil(publicAfterReclaimIntent)
        try await database!.close()
        database = nil

        // This models a process dying after the reachability transaction
        // commits but before the unlink.  Reopen consumes only lifecycle
        // metadata, sees no blob row, unlinks the private file, then clears
        // the durable reclaiming intent.
        let reopened = try await fixture.open()
        defer { Task { try? await reopened.close() } }
        XCTAssertFalse(FileManager.default.fileExists(atPath: casPath.path))
        let connection = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(
                in: fixture.root, did: fixture.author
            ).path)
        )
        let lifecycle = try await connection.query(
            "SELECT 1 FROM blob_cas_lifecycle WHERE digest_hex = ?",
            [.text(Hex.encode(try CID.parse(reference.cid).multihash.digest))]
        )
        XCTAssertTrue(lifecycle.isEmpty)
        try await connection.close()
    }

    func testLegacyMigrationSerializesWithLastReferenceRemoval() async throws {
        let fixture = try Fixture()
        var seeded: SQLiteAccountDatabase? = try await fixture.open()
        let payload = Data("legacy lifecycle interleave".utf8)
        let legacyCID = "sha256:\(Hex.encode(SHA256.hash(data: payload)))"
        let reference = BlobReference(cid: legacyCID, namespace: .space(fixture.space))
        try await seeded!.close()
        seeded = nil
        try await insertLegacyBlob(
            fixture: fixture,
            cid: legacyCID,
            payload: payload,
            byteCount: payload.count
        )

        let migrator = try await fixture.open()
        let remover = try await fixture.open()
        defer {
            Task {
                try? await remover.close()
                try? await migrator.close()
            }
        }
        let barrier = BlobLifecycleBarrier()
        await migrator.installTestingHooks(
            SQLiteTestingHooks(beforeLegacyBlobMigrationCommit: {
                try await barrier.pause()
            })
        )

        let migration = Task { try await migrator.blobData(for: reference) }
        await barrier.waitUntilPaused()
        let removalStarted = AsyncSignal()
        let removeLastReference = Task {
            await removalStarted.signal()
            try await remover.removeBlobReference(reference)
        }
        await removalStarted.wait()
        for _ in 0 ..< 20 { await Task.yield() }
        await barrier.release()

        let migratedPayload = try await migration.value
        XCTAssertEqual(migratedPayload, payload)
        try await removeLastReference.value
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: try privateCASPath(
                    fixture: fixture,
                    digestHex: Hex.encode(SHA256.hash(data: payload))
                ).path
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await migrator.blobData(for: reference)
        )
    }

    func testFailedCASStagingLeavesNoLifecycleOrPrivateFile() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        let payload = Data("rollback private CAS stage".utf8)
        let cid = CID.fromBlob(payload).string
        let casPath = try privateCASPath(fixture: fixture, cid: cid)
        await database.installTestingHooks(
            SQLiteTestingHooks(beforeBlobReferenceCommit: {
                throw InjectedTransactionFailure()
            })
        )
        await XCTAssertThrowsErrorAsync(
            try await database.putBlob(payload, namespace: .space(fixture.space))
        ) { error in
            XCTAssertTrue(error is InjectedTransactionFailure)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: casPath.path))
        await database.installTestingHooks(SQLiteTestingHooks())
        let recovered = try await database.putBlob(
            payload,
            namespace: .space(fixture.space)
        )
        XCTAssertEqual(recovered.cid, cid)
        XCTAssertTrue(FileManager.default.fileExists(atPath: casPath.path))
    }

    func testPreV4BlobSchemaRestartDefersLegacyBodyMaterialization() async throws {
        let fixture = try Fixture()
        var seeded: SQLiteAccountDatabase? = try await fixture.open()
        try await seeded!.close()
        seeded = nil

        let payload = Data(repeating: 0x61, count: 2 * 1_024 * 1_024)
        let legacyCID = "sha256:\(Hex.encode(SHA256.hash(data: payload)))"
        let reference = BlobReference(cid: legacyCID, namespace: .space(fixture.space))
        try await installPreV4BlobSchema(
            fixture: fixture,
            cid: legacyCID,
            payload: payload
        )

        let upgraded = try await fixture.open()
        let metadataConnection = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(
                in: fixture.root, did: fixture.author
            ).path)
        )
        let beforeRead = try await metadataConnection.query(
            "SELECT storage_kind, byte_count FROM blob_payloads WHERE cid = ?",
            [.text(legacyCID)]
        )
        let preRead = try XCTUnwrap(beforeRead.first)
        XCTAssertEqual(preRead.column("storage_kind")?.string, "legacy-sqlite")
        XCTAssertTrue(preRead.column("byte_count")?.isNull == true)
        try await metadataConnection.close()

        // No startup migration read has materialized or validated this body.
        // The exact authorized compatibility read performs that work and
        // preserves private-only reachability during CAS conversion.
        let authorizedLegacyRead = try await upgraded.blobData(for: reference)
        XCTAssertEqual(authorizedLegacyRead, payload)
        let legacyPublicRead = try await upgraded.publicBlobData(cid: legacyCID)
        XCTAssertNil(legacyPublicRead)
        try await upgraded.close()

        let afterConnection = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(
                in: fixture.root, did: fixture.author
            ).path)
        )
        let afterRead = try await afterConnection.query(
            "SELECT storage_kind, byte_count, length(payload) AS payload_size FROM blob_payloads WHERE cid = ?",
            [.text(legacyCID)]
        )
        let postRead = try XCTUnwrap(afterRead.first)
        XCTAssertEqual(postRead.column("storage_kind")?.string, "cas-v1")
        XCTAssertEqual(postRead.column("byte_count")?.integer, payload.count)
        XCTAssertEqual(postRead.column("payload_size")?.integer, 0)
        try await afterConnection.close()
    }

    private func privateCASPath(
        fixture: Fixture,
        cid: String
    ) throws -> URL {
        let parsed = try CID.parse(cid)
        return try privateCASPath(
            fixture: fixture,
            digestHex: Hex.encode(parsed.multihash.digest)
        )
    }

    private func privateCASPath(
        fixture: Fixture,
        digestHex: String
    ) throws -> URL {
        XCTAssertEqual(digestHex.count, 64)
        return SQLiteLayout.accountDatabase(in: fixture.root, did: fixture.author)
            .deletingLastPathComponent()
            .appending(path: "permissioned-blob-cas")
            .appending(path: Hex.encode(SHA256.hash(data: Data(fixture.author.utf8))))
            .appending(path: String(digestHex.prefix(2)))
            .appending(path: "\(digestHex).blob")
    }

    private func insertLegacyBlob(
        fixture: Fixture,
        cid: String,
        payload: Data,
        byteCount: Int
    ) async throws {
        let connection = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(
                in: fixture.root, did: fixture.author
            ).path)
        )
        _ = try await connection.query(
            """
            INSERT INTO blob_payloads(cid, payload, storage_kind, byte_count)
            VALUES (?, ?, 'legacy-sqlite', ?)
            """,
            [.text(cid), payload.sqliteData!, .integer(byteCount)]
        )
        _ = try await connection.query(
            """
            INSERT INTO blob_namespace_references(cid, namespace_kind, space_uri)
            VALUES (?, 'space', ?)
            """,
            [.text(cid), .text(fixture.space.rawValue)]
        )
        try await connection.close()
    }

    private func installPreV4BlobSchema(
        fixture: Fixture,
        cid: String,
        payload: Data
    ) async throws {
        let connection = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(
                in: fixture.root, did: fixture.author
            ).path)
        )
        _ = try await connection.query("PRAGMA foreign_keys=OFF")
        _ = try await connection.query("BEGIN IMMEDIATE")
        do {
            _ = try await connection.query("DROP TABLE blob_namespace_references")
            _ = try await connection.query("DROP TABLE blob_payloads")
            _ = try await connection.query("DROP TABLE blob_cas_lifecycle")
            _ = try await connection.query(
                "CREATE TABLE blob_payloads (cid TEXT PRIMARY KEY, payload BLOB NOT NULL)"
            )
            _ = try await connection.query(
                """
                CREATE TABLE blob_namespace_references (
                    cid TEXT NOT NULL REFERENCES blob_payloads(cid) ON DELETE CASCADE,
                    namespace_kind TEXT NOT NULL CHECK(namespace_kind IN ('public', 'space')),
                    space_uri TEXT NOT NULL,
                    PRIMARY KEY(cid, namespace_kind, space_uri),
                    CHECK(
                        (namespace_kind = 'public' AND space_uri = '')
                        OR (namespace_kind = 'space' AND length(space_uri) > 0)
                    )
                )
                """
            )
            _ = try await connection.query(
                "INSERT INTO blob_payloads(cid, payload) VALUES (?, ?)",
                [.text(cid), payload.sqliteData!]
            )
            _ = try await connection.query(
                """
                INSERT INTO blob_namespace_references(cid, namespace_kind, space_uri)
                VALUES (?, 'space', ?)
                """,
                [.text(cid), .text(fixture.space.rawValue)]
            )
            _ = try await connection.query(
                "DELETE FROM permissioned_repository_migrations WHERE version IN (4, 5, 6)"
            )
            _ = try await connection.query("COMMIT")
        } catch {
            _ = try? await connection.query("ROLLBACK")
            try await connection.close()
            throw error
        }
        _ = try await connection.query("PRAGMA foreign_keys=ON")
        try await connection.close()
    }

    func testPrivateCASStreams256MiBInBoundedChunksWhenOptedIn() async throws {
        try XCTSkipUnless(
            ProcessInfo.processInfo.environment["SWAN_BLOB_STRESS"] == "1",
            "set SWAN_BLOB_STRESS=1 to run the 256 MiB bounded-stream harness"
        )
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        // Permissioned blob reads are intentionally reachable only through a
        // live repository state. Seed the smallest valid repository before
        // measuring the 256 MiB stream; otherwise this harness exercises the
        // authorization guard rather than the bounded body path.
        _ = try await fixture.commitFirst(on: database)
        let payload = Data(repeating: 0x5a, count: 256 * 1_024 * 1_024)
        let reference = try await database.putBlob(
            payload,
            namespace: .space(fixture.space)
        )
        let maybeBlob = try await database.permissionedBlob(
            space: fixture.space, author: fixture.author, cid: reference.cid
        )
        let blob = try XCTUnwrap(maybeBlob)
        var received = 0
        var maximumChunk = 0
        try await blob.body.streamBody(maximumChunkBytes: 64 * 1_024) { chunk in
            received += chunk.count
            maximumChunk = max(maximumChunk, chunk.count)
        }
        XCTAssertEqual(received, payload.count)
        XCTAssertLessThanOrEqual(maximumChunk, 64 * 1_024)
    }

    func testAtomicBatchUsesOneRevisionAndOrderedOperationIndexes() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }

        let result = try await database.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try fixture.tid(0),
            writes: [
                .put(uri: fixture.first, value: fixture.firstValue, cid: fixture.firstCID),
                .put(uri: fixture.second, value: fixture.secondValue, cid: fixture.secondCID),
            ],
        )

        XCTAssertEqual(result.state.revision, 1)
        XCTAssertEqual(
            result.entries.map(\.cursor),
            [
                PersistedOplogCursor(revision: 1, index: 0),
                PersistedOplogCursor(revision: 1, index: 1),
            ]
        )
        guard case let .incremental(remainingEntries) = try await database.spaceOplog(
            space: fixture.space,
            author: fixture.author,
            after: PersistedOplogCursor(revision: 1, index: 0)
        ) else {
            return XCTFail("cursor inside the current commit should stay incremental")
        }
        XCTAssertEqual(
            remainingEntries.map(\.cursor),
            [PersistedOplogCursor(revision: 1, index: 1)]
        )
        let loadedSnapshot = try await database.repositorySnapshot(
            space: fixture.space,
            author: fixture.author
        )
        let snapshot = try XCTUnwrap(loadedSnapshot)
        XCTAssertEqual(snapshot.records.map(\.revision), [1, 1])
    }

    func testRetentionReportsFullRecoveryGapAndReturnsNormalIncrementalRange() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open(retention: 2)
        defer { Task { try? await database.close() } }

        _ = try await fixture.commitFirst(on: database)
        _ = try await database.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 1,
            requestID: UUID(),
            wireRevision: try fixture.tid(1),
            writes: [.put(uri: fixture.second, value: fixture.secondValue, cid: fixture.secondCID)],
        )
        _ = try await database.apply(
            space: fixture.space,
            author: fixture.author,
            expectedRevision: 2,
            requestID: UUID(),
            wireRevision: try fixture.tid(2),
            writes: [.put(uri: fixture.third, value: fixture.thirdValue, cid: fixture.thirdCID)],
        )

        guard case let .fullRecoveryRequired(snapshot) = try await database.spaceOplog(
            space: fixture.space,
            author: fixture.author,
            since: 0
        ) else {
            return XCTFail("cursor before retained revision must require a full CAR recovery")
        }
        XCTAssertEqual(snapshot.state.revision, 3)
        XCTAssertEqual(snapshot.records.count, 3)

        guard case let .incremental(entries) = try await database.spaceOplog(
            space: fixture.space,
            author: fixture.author,
            since: 1
        ) else {
            return XCTFail("cursor directly before the retained range should be incremental")
        }
        XCTAssertEqual(entries.map(\.revision), [2, 3])
    }

    func testPublicAndPermissionedNamespaceAPIsCannotCrossRead() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close() } }
        let privateOnly = try PublicRecordURI(
            "at://did:plc:alice/app.bsky.feed.post/private-only"
        )
        let publicOnlySpaceURI = try SpaceRecordURI(
            space: fixture.space,
            author: fixture.author,
            collection: "app.bsky.feed.post",
            rkey: "public-only"
        )
        let publicOnly = try PublicRecordURI(
            "at://did:plc:alice/app.bsky.feed.post/public-only"
        )

        _ = try await fixture.commitFirst(on: database)
        try await database.putPublicRecord(
            uri: publicOnly,
            value: Data("public".utf8),
            cid: "cid:public",
            revision: 7
        )

        let privateAsPublic = try await database.publicRecord(privateOnly)
        let publicAsPrivate = try await database.spaceRecord(publicOnlySpaceURI)
        let publicRecord = try await database.publicRecord(publicOnly)
        let privateRecord = try await database.spaceRecord(fixture.first)
        XCTAssertNil(privateAsPublic)
        XCTAssertNil(publicAsPrivate)
        XCTAssertEqual(publicRecord?.value, Data("public".utf8))
        XCTAssertEqual(privateRecord?.value, fixture.firstValue)
    }

    func testControlStorePersistsReplayStateAndPurgesExpiredMetadata() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanControlStoreTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let binding = OAuthClientBinding(
            issuer: "https://swan.example",
            clientID: "https://client.example/metadata",
            redirectURI: "https://client.example/callback",
            scopes: ["atproto"],
            dpopJKT: String(repeating: "C", count: 43)
        )
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let metadata = OAuthCachedClientMetadata(
            clientID: binding.clientID,
            document: Data("{\"client_id\":\"example\"}".utf8),
            expiresAt: now.addingTimeInterval(1)
        )
        try await database.cacheClientMetadata(metadata, now: now)
        let cachedMetadata = try await database.cachedClientMetadata(
            clientID: binding.clientID,
            now: now
        )
        XCTAssertEqual(cachedMetadata, metadata)

        let request = OAuthPushedAuthorizationRequest(
            requestDigest: Data(repeating: 0x11, count: 32),
            binding: binding,
            state: "state=must-round-trip",
            stateDigest: Data(repeating: 0x22, count: 32),
            codeChallengeS256: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            expiresAt: now.addingTimeInterval(30)
        )
        try await database.storePushedAuthorizationRequest(request, now: now)
        let consumed = try await database.consumePushedAuthorizationRequest(
            requestDigest: request.requestDigest,
            binding: binding,
            now: now
        )
        XCTAssertEqual(consumed.state, "state=must-round-trip")
        let duplicateState = OAuthPushedAuthorizationRequest(
            requestDigest: Data(repeating: 0x33, count: 32),
            binding: binding,
            state: request.state,
            stateDigest: request.stateDigest,
            codeChallengeS256: request.codeChallengeS256,
            expiresAt: request.expiresAt
        )
        await XCTAssertThrowsErrorAsync(
            try await database.storePushedAuthorizationRequest(duplicateState, now: now)
        ) { error in
            XCTAssertEqual(error as? OAuthControlStoreError, .replayDetected)
        }
        let expiredMetadata = try await database.cachedClientMetadata(
            clientID: binding.clientID,
            now: now.addingTimeInterval(2)
        )
        XCTAssertNil(expiredMetadata)
        let firstReplayClaim = try await database.claimDPoPReplay(
            digest: Data(repeating: 0x44, count: 32),
            expiresAt: now.addingTimeInterval(30),
            now: now
        )
        XCTAssertTrue(firstReplayClaim)
        try await database.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        let secondReplayClaim = try await reopened.claimDPoPReplay(
            digest: Data(repeating: 0x44, count: 32),
            expiresAt: now.addingTimeInterval(30),
            now: now.addingTimeInterval(1)
        )
        XCTAssertFalse(secondReplayClaim)
        let reclaimedReplay = try await reopened.claimDPoPReplay(
            digest: Data(repeating: 0x44, count: 32),
            expiresAt: now.addingTimeInterval(60),
            now: now.addingTimeInterval(31)
        )
        XCTAssertTrue(reclaimedReplay)
        try await reopened.close()
    }

    func testControlStoreRejectsUnboundOrMismatchedFamiliesAndFailsClosedForCorruptBindings() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanControlStoreBindingsTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let familyID = UUID()
        let binding = OAuthClientBinding(
            issuer: "https://swan.example",
            clientID: "https://client.example/metadata",
            redirectURI: "https://client.example/callback",
            scopes: ["atproto"],
            dpopJKT: String(repeating: "D", count: 43)
        )
        let family = OAuthTokenFamily(
            familyID: familyID,
            subject: "did:plc:alice",
            binding: binding,
            expiresAt: now.addingTimeInterval(600)
        )
        let tokens = OAuthIssuedTokenDigests(
            familyID: familyID,
            accessTokenDigest: Data(repeating: 0xA1, count: 32),
            refreshTokenDigest: Data(repeating: 0xB2, count: 32),
            accessExpiresAt: now.addingTimeInterval(60),
            refreshExpiresAt: now.addingTimeInterval(600)
        )
        let database = try await SQLiteControlDatabase(dataDirectory: root)

        for invalidJKT in [nil, "", "not-a-jkt"] as [String?] {
            let invalidFamily = OAuthTokenFamily(
                familyID: UUID(),
                subject: "did:plc:alice",
                binding: OAuthClientBinding(
                    issuer: binding.issuer,
                    clientID: binding.clientID,
                    redirectURI: binding.redirectURI,
                    scopes: binding.scopes,
                    dpopJKT: invalidJKT
                ),
                expiresAt: family.expiresAt
            )
            let invalidTokens = OAuthIssuedTokenDigests(
                familyID: invalidFamily.familyID,
                accessTokenDigest: Data(repeating: UInt8(0xC0 + (invalidJKT?.count ?? 0)), count: 32),
                refreshTokenDigest: Data(repeating: UInt8(0xD0 + (invalidJKT?.count ?? 0)), count: 32),
                accessExpiresAt: tokens.accessExpiresAt,
                refreshExpiresAt: tokens.refreshExpiresAt
            )
            await XCTAssertThrowsErrorAsync(
                try await database.issueTokenPair(
                    family: invalidFamily,
                    tokens: invalidTokens,
                    now: now
                )
            ) { error in
                XCTAssertEqual(error as? OAuthControlStoreError, .invalidInput)
            }
        }

        let mismatchedTokens = OAuthIssuedTokenDigests(
            familyID: UUID(),
            accessTokenDigest: tokens.accessTokenDigest,
            refreshTokenDigest: tokens.refreshTokenDigest,
            accessExpiresAt: tokens.accessExpiresAt,
            refreshExpiresAt: tokens.refreshExpiresAt
        )
        await XCTAssertThrowsErrorAsync(
            try await database.issueTokenPair(family: family, tokens: mismatchedTokens, now: now)
        ) { error in
            XCTAssertEqual(error as? OAuthControlStoreError, .invalidInput)
        }
        let revokedFamily = OAuthTokenFamily(
            familyID: UUID(),
            subject: family.subject,
            binding: binding,
            expiresAt: family.expiresAt,
            revokedAt: now
        )
        let revokedTokens = OAuthIssuedTokenDigests(
            familyID: revokedFamily.familyID,
            accessTokenDigest: Data(repeating: 0xE1, count: 32),
            refreshTokenDigest: Data(repeating: 0xF2, count: 32),
            accessExpiresAt: tokens.accessExpiresAt,
            refreshExpiresAt: tokens.refreshExpiresAt
        )
        await XCTAssertThrowsErrorAsync(
            try await database.issueTokenPair(family: revokedFamily, tokens: revokedTokens, now: now)
        ) { error in
            XCTAssertEqual(error as? OAuthControlStoreError, .invalidInput)
        }

        try await database.issueTokenPair(family: family, tokens: tokens, now: now)
        let codeDigest = Data(repeating: 0xC3, count: 32)
        let code = OAuthAuthorizationCode(
            codeDigest: codeDigest,
            familyID: UUID(),
            subject: family.subject,
            binding: binding,
            codeChallengeS256: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            expiresAt: now.addingTimeInterval(60),
            familyExpiresAt: family.expiresAt
        )
        try await database.storeAuthorizationCode(code, now: now)
        try await database.close()

        let direct = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.controlDatabase(in: root).path)
        )
        _ = try await direct.query(
            "UPDATE oauth_control_token_families SET dpop_jkt = NULL"
        )
        try await direct.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        await XCTAssertThrowsErrorAsync(
            try await reopened.validatedAccessToken(
                accessTokenDigest: tokens.accessTokenDigest,
                requireActiveSubject: false,
                now: now
            )
        ) { error in
            XCTAssertEqual(error as? OAuthControlStoreError, .malformedRecord)
        }
        await XCTAssertThrowsErrorAsync(
            try await reopened.refreshTokenFamily(
                refreshTokenDigest: try XCTUnwrap(tokens.refreshTokenDigest),
                now: now
            )
        ) { error in
            XCTAssertEqual(error as? OAuthControlStoreError, .malformedRecord)
        }
        await XCTAssertThrowsErrorAsync(
            try await reopened.authorizationCode(codeDigest: codeDigest, now: now)
        ) { error in
            XCTAssertEqual(error as? OAuthControlStoreError, .malformedRecord)
        }
        try await reopened.close()
    }

    func testControlStoreAddsCompleteConfidentialKeyColumnsToExistingDatabase() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanControlStoreMigrationTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o700)],
            ofItemAtPath: root.path
        )
        let path = SQLiteLayout.controlDatabase(in: root).path
        let legacy = try await SQLiteConnection.open(storage: .file(path: path))
        _ = try await legacy.query(
            """
            CREATE TABLE oauth_control_token_families (
                family_id TEXT PRIMARY KEY, subject TEXT NOT NULL,
                issuer TEXT NOT NULL, client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL, scopes BLOB NOT NULL,
                dpop_jkt TEXT, client_assertion_key_id TEXT,
                expires_at INTEGER NOT NULL, revoked_at INTEGER
            )
            """
        )
        _ = try await legacy.query(
            """
            CREATE TABLE oauth_control_par_requests (
                request_digest BLOB PRIMARY KEY, issuer TEXT NOT NULL,
                client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
                scopes BLOB NOT NULL, dpop_jkt TEXT,
                client_assertion_key_id TEXT, state TEXT NOT NULL,
                state_digest BLOB NOT NULL, code_challenge_method TEXT NOT NULL,
                code_challenge_s256 TEXT NOT NULL, expires_at INTEGER NOT NULL,
                consumed_at INTEGER
            )
            """
        )
        try await legacy.close()
        try lockDownLegacySQLiteDatabase(URL(fileURLWithPath: path), dataDirectory: root)

        let migrated = try await SQLiteControlDatabase(dataDirectory: root)
        try await migrated.close()
        let inspected = try await SQLiteConnection.open(storage: .file(path: path))
        for table in ["oauth_control_token_families", "oauth_control_par_requests"] {
            let columns = try await inspected.query("PRAGMA table_info(\(table))")
                .compactMap { $0.column("name")?.string }
            XCTAssertTrue(columns.contains("client_assertion_algorithm"))
            XCTAssertTrue(columns.contains("client_assertion_jkt"))
        }
        try await inspected.close()
    }

    func testAccountControlRestartPersistsRegistryButLookupExcludesVerifier() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        var database: SQLiteControlDatabase? = try await SQLiteControlDatabase(dataDirectory: root)
        let registration = try controlRegistration(
            did: "did:plc:abcdefghijklmnopqrstuvwx",
            handle: "alice.example.com",
            createdAt: now
        )
        let created = try await database!.createAccount(registration)
        XCTAssertEqual(created.did, registration.did)
        XCTAssertEqual(created.canonicalHandle, registration.canonicalHandle)
        XCTAssertEqual(created.status, .active)
        XCTAssertEqual(created.credentialState, .configured)
        XCTAssertEqual(created.signingKey?.generation, 1)
        XCTAssertEqual(created.rotationKey?.reference, "account-rotation:1")
        XCTAssertFalse(String(describing: created).contains(registration.passwordVerifier))
        try await database!.close()
        database = nil

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        let byDIDResult = try await reopened.account(did: registration.did)
        let byHandleResult = try await reopened.account(canonicalHandle: registration.canonicalHandle)
        let byDID = try XCTUnwrap(byDIDResult)
        let byHandle = try XCTUnwrap(byHandleResult)
        XCTAssertEqual(byDID, byHandle)
        XCTAssertEqual(byDID.createdAt, now)
        XCTAssertEqual(byDID.updatedAt, now)
        let credential = try await reopened.credential(did: registration.did)
        XCTAssertEqual(credential?.verifier, registration.passwordVerifier)
        try await reopened.close()
    }

    func testAccountControlDuplicateDIDAndHandleRacesAreTypedAndAtomic() async throws {
        let handleRoot = try controlRoot()
        defer { try? FileManager.default.removeItem(at: handleRoot) }
        let handleFirst = try await SQLiteControlDatabase(dataDirectory: handleRoot)
        let handleSecond = try await SQLiteControlDatabase(dataDirectory: handleRoot)
        defer {
            Task {
                try? await handleFirst.close()
                try? await handleSecond.close()
            }
        }
        let handleResults = await controlCreateRace(
            first: handleFirst,
            second: handleSecond,
            firstRegistration: try controlRegistration(
                did: "did:plc:abcdefghijklmnopqrstuvwx",
                handle: "race.example.com"
            ),
            secondRegistration: try controlRegistration(
                did: "did:plc:bcdefghijklmnopqrstuvwxy",
                handle: "race.example.com"
            )
        )
        XCTAssertEqual(handleResults.successes, 1)
        XCTAssertEqual(handleResults.errors, [.duplicateHandle])

        let didRoot = try controlRoot()
        defer { try? FileManager.default.removeItem(at: didRoot) }
        let didFirst = try await SQLiteControlDatabase(dataDirectory: didRoot)
        let didSecond = try await SQLiteControlDatabase(dataDirectory: didRoot)
        defer {
            Task {
                try? await didFirst.close()
                try? await didSecond.close()
            }
        }
        let didResults = await controlCreateRace(
            first: didFirst,
            second: didSecond,
            firstRegistration: try controlRegistration(
                did: "did:plc:abcdefghijklmnopqrstuvwx",
                handle: "alice-one.example.com"
            ),
            secondRegistration: try controlRegistration(
                did: "did:plc:abcdefghijklmnopqrstuvwx",
                handle: "alice-two.example.com"
            )
        )
        XCTAssertEqual(didResults.successes, 1)
        XCTAssertEqual(didResults.errors, [.duplicateDID])
    }

    func testAccountControlMigrationMakesLegacyAccountsExplicitlyCredentialless() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let path = SQLiteLayout.controlDatabase(in: root).path
        let legacy = try await SQLiteConnection.open(storage: .file(path: path))
        _ = try await legacy.query(
            """
            CREATE TABLE accounts (
                did TEXT PRIMARY KEY,
                handle TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        _ = try await legacy.query(
            "INSERT INTO accounts(did, handle, status, created_at) VALUES (?, ?, ?, ?)",
            [
                .text("did:plc:abcdefghijklmnopqrstuvwx"),
                .text("Alice.Example.COM"),
                .text("active"),
                .integer(1_750_000_000_000_000),
            ]
        )
        try await legacy.close()
        try lockDownLegacySQLiteDatabase(URL(fileURLWithPath: path), dataDirectory: root)

        let migrated = try await SQLiteControlDatabase(dataDirectory: root)
        let migratedAccount = try await migrated.account(did: "did:plc:abcdefghijklmnopqrstuvwx")
        let account = try XCTUnwrap(migratedAccount)
        XCTAssertEqual(account.canonicalHandle, "alice.example.com")
        XCTAssertEqual(account.credentialState, .missing)
        XCTAssertNil(account.signingKey)
        XCTAssertNil(account.rotationKey)
        let legacyCredential = try await migrated.credential(did: account.did)
        XCTAssertNil(legacyCredential)
        try await migrated.close()
    }

    func testAccountControlRejectsInvalidInputsAndStoresNoRawPasswordOrPrivateKeyBytes() async throws {
        XCTAssertThrowsError(try AccountControlStatus(rawValue: "Active"))
        XCTAssertThrowsError(try AccountControlStatus(rawValue: "future status"))
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        await XCTAssertThrowsErrorAsync(
            try await database.account(canonicalHandle: "Alice.Example.COM")
        ) { error in
            XCTAssertEqual(error as? AccountControlStoreError, .invalidInput)
        }
        XCTAssertThrowsError(
            try controlRegistration(
                did: "did:plc:abcdefghijklmnopqrstuvwx",
                handle: "alice.3com"
            )
        ) { error in
            XCTAssertEqual(error as? AccountControlStoreError, .invalidInput)
        }
        await XCTAssertThrowsErrorAsync(
            try await database.createAccount(
                AccountControlRegistration(
                    did: "did:key:abcdefghijklmnopqrstuvwx",
                    canonicalHandle: "invalid.example.com",
                    passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                    signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
                    rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1)
                )
            )
        ) { error in
            XCTAssertEqual(error as? AccountControlStoreError, .invalidInput)
        }
        let directStatusWrite = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.controlDatabase(in: root).path)
        )
        await XCTAssertThrowsErrorAsync(
            try await directStatusWrite.query(
                "INSERT INTO accounts(did, handle, status, created_at) VALUES (?, ?, ?, ?)",
                [
                    .text("did:plc:bcdefghijklmnopqrstuvwxy"),
                    .text("status.example.com"),
                    .text("invalid status"),
                    .integer(1_750_000_000_000_000),
                ]
            )
        )
        try await directStatusWrite.close()
        let registration = try controlRegistration(
            did: "did:plc:abcdefghijklmnopqrstuvwx",
            handle: "alice.example.com"
        )
        _ = try await database.createAccount(registration)
        try await database.close()

        let bytes = try Data(contentsOf: SQLiteLayout.controlDatabase(in: root))
        let databaseText = String(decoding: bytes, as: UTF8.self)
        XCTAssertFalse(databaseText.contains("raw-password-never-stored"))
        XCTAssertFalse(databaseText.contains("\u{01}\u{02}\u{03}\u{04}"))
        XCTAssertFalse(databaseText.contains("private-key-export-envelope"))
        let direct = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.controlDatabase(in: root).path)
        )
        let columns = try await direct.query("PRAGMA table_info(accounts)")
            .compactMap { $0.column("name")?.string }
        XCTAssertFalse(columns.contains(where: { $0.contains("private") || $0.contains("key_bytes") }))
        try await direct.close()
    }

    func testAccountControlRejectsUnknownAliasesForEveryKnownStatusToken() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }
        let registration = try controlRegistration(
            did: "did:plc:abcdefghijklmnopqrstuvwx",
            handle: "aliases.example.com"
        )
        let account = try await database.createAccount(registration)
        let knownStatuses: [AccountControlStatus] = [
            .active, .deactivated, .deleted, .takendown, .suspended,
            .desynchronized, .throttled,
        ]

        for known in knownStatuses {
            let alias = AccountControlStatus.unknown(known.rawValue)
            XCTAssertFalse(alias.isCanonicalValue, "unknown alias for \(known.rawValue)")
            XCTAssertFalse(AccountStatusTransitionPolicy.standard.permits(from: .deactivated, to: alias))
            XCTAssertThrowsError(
                try AccountStatusTransitionPolicy.standard.validate(from: .deactivated, to: alias)
            ) { error in
                XCTAssertEqual(error as? AccountControlStoreError, .invalidStatus)
            }
            XCTAssertThrowsError(
                try AccountControlAccount(
                    did: account.did,
                    canonicalHandle: account.canonicalHandle,
                    status: alias,
                    createdAt: account.createdAt,
                    updatedAt: account.updatedAt,
                    credentialState: account.credentialState,
                    signingKey: account.signingKey,
                    rotationKey: account.rotationKey
                )
            ) { error in
                XCTAssertEqual(error as? AccountControlStoreError, .invalidStatus)
            }
            await XCTAssertThrowsErrorAsync(
                try await database.transitionStatus(
                    did: account.did,
                    to: alias,
                    declaration: .init(),
                    now: account.updatedAt.addingTimeInterval(1)
                )
            ) { error in
                XCTAssertEqual(error as? AccountControlStoreError, .invalidStatus)
            }
        }

        let reloaded = try await database.account(did: account.did)
        XCTAssertEqual(reloaded?.status, .active)
    }

    func testAccountControlKeyReferencesRejectDecodedSecretsAndMismatchedGenerations() async throws {
        let secretSentinel = "injected-private-key-bytes-never-persist"
        let injectedReference = """
        {"purpose":"account-signing","generation":1,"reference":"\(secretSentinel)"}
        """
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                AccountControlKeyReference.self,
                from: Data(injectedReference.utf8)
            )
        )
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                AccountControlKeyReference.self,
                from: Data(#"{"purpose":"account-signing","generation":1,"reference":"account-rotation:1"}"#.utf8)
            )
        )

        let signing = try AccountControlKeyReference(purpose: .signing, generation: 1)
        let mismatchedRotation = try AccountControlKeyReference(purpose: .rotation, generation: 2)
        XCTAssertThrowsError(
            try AccountControlRegistration(
                did: "did:plc:abcdefghijklmnopqrstuvwx",
                canonicalHandle: "mismatch.example.com",
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: signing,
                rotationKey: mismatchedRotation
            )
        ) { error in
            XCTAssertEqual(error as? AccountControlStoreError, .invalidInput)
        }
        XCTAssertThrowsError(
            try AccountControlAccount(
                did: "did:plc:abcdefghijklmnopqrstuvwx",
                canonicalHandle: "mismatch.example.com",
                status: .active,
                createdAt: Date(timeIntervalSince1970: 1_750_000_000),
                updatedAt: Date(timeIntervalSince1970: 1_750_000_000),
                credentialState: .configured,
                signingKey: signing,
                rotationKey: mismatchedRotation
            )
        ) { error in
            XCTAssertEqual(error as? AccountControlStoreError, .invalidInput)
        }

        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await database.createAccount(
            controlRegistration(
                did: "did:plc:abcdefghijklmnopqrstuvwx",
                handle: "references.example.com"
            )
        )
        try await database.close()
        let controlBytes = try Data(contentsOf: SQLiteLayout.controlDatabase(in: root))
        XCTAssertFalse(String(decoding: controlBytes, as: UTF8.self).contains(secretSentinel))
    }

    func testAccountControlExportMetadataOnlyPersistsCanonicalManifestDigests() async throws {
        let secretSentinel = "recovery phrase private key export payload"
        let validDigest = "sha256:" + String(repeating: "a", count: 64)
        let invalidReferences = [
            secretSentinel,
            "c2VlZC1waHJhc2U=",
            "sha256:" + String(repeating: "A", count: 64),
            "sha256:" + String(repeating: "a", count: 63),
        ]
        for reference in invalidReferences {
            XCTAssertThrowsError(try AccountExportMetadata(reference: reference))
            let encoded = "{\"declaredAt\":0,\"reference\":\"\(reference)\"}"
            XCTAssertThrowsError(
                try JSONDecoder().decode(AccountExportMetadata.self, from: Data(encoded.utf8))
            )
        }
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                AccountTombstoneMetadata.self,
                from: Data(#"{"declaredAt":-1000000000,"reason":"invalid"}"#.utf8)
            )
        )
        XCTAssertThrowsError(
            try JSONDecoder().decode(
                AccountTombstoneMetadata.self,
                from: Data(#"{"declaredAt":0,"reason":"operator\ntext"}"#.utf8)
            )
        )

        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let registration = try controlRegistration(
            did: "did:plc:abcdefghijklmnopqrstuvwx",
            handle: "exports.example.com",
            createdAt: now
        )
        _ = try await database.createAccount(registration)
        let transitioned = try await database.transitionStatus(
            did: registration.did,
            to: .active,
            declaration: AccountLifecycleDeclaration(
                export: try AccountExportMetadata(declaredAt: now, reference: validDigest)
            ),
            now: now.addingTimeInterval(1)
        )
        XCTAssertEqual(transitioned.export?.reference, validDigest)
        try await database.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        let persisted = try await reopened.account(did: registration.did)
        XCTAssertEqual(persisted?.export?.reference, validDigest)
        try await reopened.close()

        let controlBytes = try Data(contentsOf: SQLiteLayout.controlDatabase(in: root))
        let controlText = String(decoding: controlBytes, as: UTF8.self)
        XCTAssertTrue(controlText.contains(validDigest))
        XCTAssertFalse(controlText.contains(secretSentinel))
        XCTAssertFalse(controlText.contains("c2VlZC1waHJhc2U="))
    }

    func testAccountDeactivationAtomicallyRevokesEveryLegacyFamily() async throws {
        let root = try controlRoot()
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        addTeardownBlock { [database, root] in
            try? await database.close()
            try? FileManager.default.removeItem(at: root)
        }
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let createdAt = Date(timeIntervalSince1970: 1_750_000_000)
        _ = try await database.createAccount(
            controlRegistration(
                did: did,
                handle: "legacy-revocation.example.com",
                createdAt: createdAt
            )
        )
        for index in 0 ..< 2 {
            try await database.createLegacySessionFamily(
                familyID: "legacy-family-\(index)",
                did: did,
                appPasswordID: nil,
                accessDigest: Data(repeating: UInt8(0x31 + index * 2), count: 32),
                accessExpiresAt: createdAt.addingTimeInterval(3_600),
                refreshDigest: Data(repeating: UInt8(0x32 + index * 2), count: 32),
                refreshExpiresAt: createdAt.addingTimeInterval(90 * 86_400),
                now: createdAt
            )
        }

        // Force the last step of the lifecycle cleanup to fail. The account
        // status and family timestamps must roll back with the token deletion.
        _ = try await database.connection.query(
            """
            CREATE TEMP TRIGGER fail_legacy_token_delete
            BEFORE DELETE ON legacy_session_tokens
            BEGIN
                SELECT RAISE(ABORT, 'forced legacy token delete failure');
            END
            """
        )
        let transitionTime = createdAt.addingTimeInterval(10)
        do {
            _ = try await database.transitionStatus(
                did: did,
                to: .deactivated,
                declaration: .init(),
                now: transitionTime
            )
            XCTFail("the injected delete failure must abort deactivation")
        } catch {}

        let rolledBackAccount = try await database.account(did: did)
        XCTAssertEqual(rolledBackAccount?.status, .active)
        let rolledBackFamilies = try await database.connection.query(
            "SELECT revoked_at FROM legacy_session_families WHERE did = ? ORDER BY family_id",
            [.text(did)]
        )
        XCTAssertEqual(rolledBackFamilies.count, 2)
        XCTAssertTrue(rolledBackFamilies.allSatisfy { $0.column("revoked_at")?.isNull == true })
        let rolledBackTokens = try await database.connection.query(
            "SELECT COUNT(*) AS token_count FROM legacy_session_tokens"
        )
        XCTAssertEqual(rolledBackTokens.first?.column("token_count")?.integer, 4)

        _ = try await database.connection.query("DROP TRIGGER fail_legacy_token_delete")
        _ = try await database.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: .init(),
            now: transitionTime
        )

        let revokedFamilies = try await database.connection.query(
            "SELECT revoked_at FROM legacy_session_families WHERE did = ? ORDER BY family_id",
            [.text(did)]
        )
        let expectedTimestamp = Int(transitionTime.timeIntervalSince1970 * 1_000_000)
        XCTAssertEqual(revokedFamilies.count, 2)
        XCTAssertEqual(
            revokedFamilies.compactMap { $0.column("revoked_at")?.integer },
            [expectedTimestamp, expectedTimestamp]
        )
        let remainingTokens = try await database.connection.query(
            "SELECT COUNT(*) AS token_count FROM legacy_session_tokens"
        )
        XCTAssertEqual(remainingTokens.first?.column("token_count")?.integer, 0)
    }

    func testTransitionWithEmissionEnqueuesAccountBatchAtomically() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        _ = try await database.createAccount(
            controlRegistration(did: did, handle: "emission.example.com")
        )
        let epoch = Date(timeIntervalSince1970: 1_750_000_000)
        _ = try await database.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: .init(),
            emitting: .init(operationID: "op-deact-1"),
            now: epoch
        )
        let pending = try await database.nextPendingLifecycleBatch(did: did)
        let batch = try XCTUnwrap(pending)
        XCTAssertEqual(batch.items.count, 1)
        let material = try JSONDecoder().decode(
            PublicFirehoseAccountMaterial.self,
            from: batch.items[0].payload
        )
        XCTAssertFalse(material.active)
        XCTAssertEqual(material.status, .deactivated)
        XCTAssertEqual(
            batch.items[0].sourceKey,
            PublicFirehoseSourceKey.account(did: did, operationID: "op-deact-1")
        )
    }

    func testSameStatusTransitionWithEmissionEnqueuesNothing() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        _ = try await database.createAccount(
            controlRegistration(did: did, handle: "noop-emission.example.com")
        )
        let epoch = Date(timeIntervalSince1970: 1_750_000_000)
        _ = try await database.transitionStatus(
            did: did,
            to: .active,
            declaration: .init(),
            emitting: .init(operationID: "op-noop-1"),
            now: epoch
        )
        let pending = try await database.nextPendingLifecycleBatch(did: did)
        XCTAssertNil(pending)
    }

    func testTransitionWithoutEmissionEnqueuesNothing() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        _ = try await database.createAccount(
            controlRegistration(did: did, handle: "silent-emission.example.com")
        )
        let epoch = Date(timeIntervalSince1970: 1_750_000_000)
        _ = try await database.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: .init(),
            now: epoch
        )
        let pending = try await database.nextPendingLifecycleBatch(did: did)
        XCTAssertNil(pending)
    }

    func testTransitionWithEmissionMapsEveryPublicModerationStatus() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        _ = try await database.createAccount(
            controlRegistration(did: did, handle: "status-sweep.example.com")
        )
        let epoch = Date(timeIntervalSince1970: 1_750_000_000)
        let sweeps: [(AccountControlStatus, PublicFirehoseAccountStatus)] = [
            (.deactivated, .deactivated),
            (.suspended, .suspended),
            (.takendown, .takendown),
            (.desynchronized, .desynchronized),
            (.throttled, .throttled),
        ]
        for (index, sweep) in sweeps.enumerated() {
            let operationID = "op-sweep-\(index)"
            _ = try await database.transitionStatus(
                did: did,
                to: sweep.0,
                declaration: .init(),
                emitting: .init(operationID: operationID),
                now: epoch.addingTimeInterval(Double(index + 1))
            )
            let pending = try await database.nextPendingLifecycleBatch(did: did)
            let batch = try XCTUnwrap(pending)
            XCTAssertEqual(batch.items.count, 1)
            let material = try JSONDecoder().decode(
                PublicFirehoseAccountMaterial.self,
                from: batch.items[0].payload
            )
            XCTAssertFalse(material.active)
            XCTAssertEqual(material.status, sweep.1)
            XCTAssertEqual(
                batch.items[0].sourceKey,
                PublicFirehoseSourceKey.account(did: did, operationID: operationID)
            )
            _ = try await database.completeLifecycleBatch(batchID: batch.batchID)
        }
        // unknown has no public representation: emission maps to nothing.
        _ = try await database.transitionStatus(
            did: did,
            to: .unknown("future-moderation-state"),
            declaration: .init(),
            emitting: .init(operationID: "op-unknown-1"),
            now: epoch.addingTimeInterval(6)
        )
        let pending = try await database.nextPendingLifecycleBatch(did: did)
        XCTAssertNil(pending)
    }

    func testAccountControlConcurrentLegacyOpenSerializesMigration() async throws {
        let root = try controlRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let path = SQLiteLayout.controlDatabase(in: root).path
        let legacy = try await SQLiteConnection.open(storage: .file(path: path))
        _ = try await legacy.query(
            """
            CREATE TABLE accounts (
                did TEXT PRIMARY KEY,
                handle TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        _ = try await legacy.query(
            "INSERT INTO accounts(did, handle, status, created_at) VALUES (?, ?, ?, ?)",
            [
                .text("did:plc:abcdefghijklmnopqrstuvwx"),
                .text("Alice.Example.COM"),
                .text("active"),
                .integer(1_750_000_000_000_000),
            ]
        )
        try await legacy.close()
        try lockDownLegacySQLiteDatabase(URL(fileURLWithPath: path), dataDirectory: root)

        // A successfully opened database owns an SQLiteNIO connection until
        // `close()` completes. Do not make it a result of a throwing group:
        // if its peer throws, `withThrowingTaskGroup` discards unretrieved
        // successful results while unwinding, which deinitializes that live
        // connection before this test can close it. Keep every outcome first,
        // then close successes on either path.
        let concurrentOpenCount = 8
        let openResults = await withTaskGroup(
            of: Result<SQLiteControlDatabase, any Error>.self,
            returning: [Result<SQLiteControlDatabase, any Error>].self
        ) { group in
            for _ in 0 ..< concurrentOpenCount {
                group.addTask {
                    do {
                        return .success(try await SQLiteControlDatabase(dataDirectory: root))
                    } catch {
                        return .failure(error)
                    }
                }
            }
            return await group.reduce(into: []) { $0.append($1) }
        }
        var databases: [SQLiteControlDatabase] = []
        var openingErrors: [any Error] = []
        for result in openResults {
            switch result {
            case let .success(database):
                databases.append(database)
            case let .failure(error):
                openingErrors.append(error)
            }
        }
        if !openingErrors.isEmpty {
            for database in databases {
                try? await database.close()
            }
            XCTFail("concurrent legacy opens failed: \(openingErrors.map { String(reflecting: $0) })")
            return
        }
        XCTAssertEqual(databases.count, concurrentOpenCount)
        let migratedAccount = try await databases[0].account(
            did: "did:plc:abcdefghijklmnopqrstuvwx"
        )
        XCTAssertEqual(migratedAccount?.canonicalHandle, "alice.example.com")
        XCTAssertEqual(migratedAccount?.credentialState, .missing)
        for database in databases {
            try await database.close()
        }

        let inspected = try await SQLiteConnection.open(storage: .file(path: path))
        let columns = try await inspected.query("PRAGMA table_info(accounts)")
            .compactMap { $0.column("name")?.string }
        XCTAssertTrue(columns.contains("password_verifier"))
        XCTAssertTrue(columns.contains("signing_key_generation"))
        XCTAssertTrue(columns.contains("export_reference"))
        try await inspected.close()
    }
    func testSimpleSpaceAuthorityRejectsTamperedPersistedFacts() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSQLiteAuthorityTamperTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let did = "did:plc:alice"
        let space = try SpaceURI(
            authority: did,
            spaceType: "app.bsky.bookmarks",
            skey: "tamper"
        )
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let authority = try DurableSimpleSpaceAuthority(
            database: database,
            credentialSecret: Data(repeating: 7, count: 32)
        )
        _ = try await authority.create(
            space: space,
            owner: did,
            configuration: try SimpleSpaceConfiguration(readPolicy: .memberList, writePolicy: .memberList),
            authorization: .accountOAuthForTesting(subject: did, scopes: ["atproto"])
        )
        try await database.close()

        let databasePath = SQLiteLayout.accountDatabase(in: root, did: did).path
        let raw = try await SQLiteConnection.open(storage: .file(path: databasePath))
        do {
            _ = try await raw.query(
                "DELETE FROM permissioned_simple_space_members WHERE space_uri = ? AND member_did = ?",
                [.text(space.rawValue), .text(did)]
            )
            _ = try await raw.query(
                "INSERT INTO permissioned_simple_space_managing_app_decisions(space_uri, user_did, access) VALUES (?, ?, 'read')",
                [.text(space.rawValue), .text("did:plc:bob")]
            )
            _ = try await raw.query(
                "INSERT INTO permissioned_simple_space_managing_app_decisions(space_uri, user_did, access) VALUES (?, ?, 'write')",
                [.text(space.rawValue), .text("did:plc:bob")]
            )
            try await raw.close()
        } catch {
            try? await raw.close()
            throw error
        }

        let reopened = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        await XCTAssertThrowsErrorAsync(
            try await reopened.simpleSpace(
                space,
                authorization: .accountOAuthForTesting(subject: did, scopes: ["atproto"])
            )
        ) { error in
            guard case .corruptDatabase = error as? SQLiteRepositoryError else {
                return XCTFail("expected a fail-closed corruption error, got \(error)")
            }
        }
        let reopenedAuthority = try DurableSimpleSpaceAuthority(
            database: reopened,
            credentialSecret: Data(repeating: 7, count: 32)
        )
        await XCTAssertThrowsErrorAsync(
            try await reopenedAuthority.issueReadCredential(
                space: space,
                user: "did:plc:bob",
                clientID: nil,
                authorization: .accountOAuthForTesting(
                    subject: "did:plc:bob",
                    scopes: ["atproto"]
                )
            )
        )
        try await reopened.close()

        // Verify corruption rejection across asymmetric read/write policy axes:
        // 1. Asymmetric: managingApp read, memberList write, corrupted with illegal write decision
        let asymmWriteSpace = try SpaceURI(authority: did, spaceType: "app.bsky.bookmarks", skey: "tamper-asymm-write")
        let asymmDb1 = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let asymmAuth1 = try DurableSimpleSpaceAuthority(
            database: asymmDb1,
            credentialSecret: Data(repeating: 7, count: 32)
        )
        _ = try await asymmAuth1.create(
            space: asymmWriteSpace,
            owner: did,
            configuration: try SimpleSpaceConfiguration(
                readPolicy: .managingApp,
                readManagingApp: "did:web:manager.example",
                writePolicy: .memberList
            ),
            authorization: .accountOAuthForTesting(subject: did, scopes: ["atproto"])
        )
        try await asymmDb1.close()

        let rawAsymm1 = try await SQLiteConnection.open(storage: .file(path: databasePath))
        do {
            _ = try await rawAsymm1.query(
                "INSERT INTO permissioned_simple_space_managing_app_decisions(space_uri, user_did, access) VALUES (?, ?, 'write')",
                [.text(asymmWriteSpace.rawValue), .text("did:plc:bob")]
            )
            try await rawAsymm1.close()
        } catch {
            try? await rawAsymm1.close()
            throw error
        }

        // October 29: a one-sided managing-app configuration is stored as a
        // managedspace on both sides (`readManagingApp ?? writeManagingApp`),
        // and stored managing-app decisions are no longer consulted or
        // validated, so a stray write decision row is inert.
        let reopenedAsymm1 = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let asymmLookup1 = try await reopenedAsymm1.simpleSpace(
            asymmWriteSpace,
            authorization: .accountOAuthForTesting(subject: did, scopes: ["atproto"])
        )
        XCTAssertEqual(
            asymmLookup1?.space.configuration.policy,
            .managed(try ManagedSpacePolicy(managingApp: "did:web:manager.example"))
        )
        try await reopenedAsymm1.close()

        // 2. Asymmetric: memberList read, managingApp write, corrupted with illegal read decision
        let asymmReadSpace = try SpaceURI(authority: did, spaceType: "app.bsky.bookmarks", skey: "tamper-asymm-read")
        let asymmDb2 = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let asymmAuth2 = try DurableSimpleSpaceAuthority(
            database: asymmDb2,
            credentialSecret: Data(repeating: 7, count: 32)
        )
        _ = try await asymmAuth2.create(
            space: asymmReadSpace,
            owner: did,
            configuration: try SimpleSpaceConfiguration(
                readPolicy: .memberList,
                writePolicy: .managingApp,
                writeManagingApp: "did:web:manager.example"
            ),
            authorization: .accountOAuthForTesting(subject: did, scopes: ["atproto"])
        )
        try await asymmDb2.close()

        let rawAsymm2 = try await SQLiteConnection.open(storage: .file(path: databasePath))
        do {
            _ = try await rawAsymm2.query(
                "INSERT INTO permissioned_simple_space_managing_app_decisions(space_uri, user_did, access) VALUES (?, ?, 'read')",
                [.text(asymmReadSpace.rawValue), .text("did:plc:bob")]
            )
            try await rawAsymm2.close()
        } catch {
            try? await rawAsymm2.close()
            throw error
        }

        // October 29: a one-sided managing-app configuration is stored as a
        // managedspace on both sides (`readManagingApp ?? writeManagingApp`),
        // and stored managing-app decisions are no longer consulted or
        // validated, so a stray read decision row is inert.
        let reopenedAsymm2 = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let asymmLookup2 = try await reopenedAsymm2.simpleSpace(
            asymmReadSpace,
            authorization: .accountOAuthForTesting(subject: did, scopes: ["atproto"])
        )
        XCTAssertEqual(
            asymmLookup2?.space.configuration.policy,
            .managed(try ManagedSpacePolicy(managingApp: "did:web:manager.example"))
        )
        try await reopenedAsymm2.close()
    }

    func testSimpleSpaceMemberPageUsesKeysetAndRejectsOversizedState() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSQLiteSimpleSpacePageTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let owner = "did:plc:alice"
        let space = try SpaceURI(
            authority: owner,
            spaceType: "app.bsky.bookmarks",
            skey: "page"
        )
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: owner)
        let authority = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
        let authorization: AuthorizationContext = .accountOAuthForTesting(
            subject: owner,
            scopes: ["atproto"]
        )
        _ = try await authority.create(
            space: space,
            owner: owner,
            configuration: try SimpleSpaceConfiguration(readPolicy: .memberList, writePolicy: .memberList),
            authorization: authorization
        )
        _ = try await database.putSimpleSpaceMembers(
            space: space,
            members: [.init(did: "did:plc:bob", read: true, write: true)],
            authorization: authorization
        )

        let first = try await authority.memberPage(
            space: space,
            limit: 1,
            cursor: nil,
            authorization: authorization
        )
        XCTAssertEqual(first.members.map(\.did), [owner])
        XCTAssertEqual(first.members.first?.read, true)
        XCTAssertEqual(first.members.first?.write, true)
        let second = try await authority.memberPage(
            space: space,
            limit: 1,
            cursor: first.cursor,
            authorization: authorization
        )
        XCTAssertEqual(second.members.map(\.did), ["did:plc:bob"])
        XCTAssertEqual(second.members.first?.read, true)
        XCTAssertEqual(second.members.first?.write, true)

        // Corrupt the durable child table with one row beyond the domain cap.
        // The page path must reject by a scalar count before it can map a page
        // into Swift strings.
        _ = try await database.connection.query(
            """
            WITH RECURSIVE n(i) AS (
                SELECT 0
                UNION ALL
                SELECT i + 1 FROM n WHERE i < ?
            )
            INSERT OR IGNORE INTO permissioned_simple_space_members(space_uri, member_did)
            SELECT ?, 'did:plc:member' || printf('%05d', i)
            FROM n
            """,
            [
                .integer(SimpleSpaceLimits.maximumMembersPerSpace),
                .text(space.rawValue),
            ]
        )
        await XCTAssertThrowsErrorAsync(
            try await authority.memberPage(
                space: space,
                limit: 1,
                cursor: nil,
                authorization: authorization
            )
        ) { error in
            guard case .corruptDatabase = error as? SQLiteRepositoryError else {
                return XCTFail("expected bounded-state corruption, got \(error)")
            }
        }
        try await database.close()
    }

    func testSimpleSpaceAuthoritySchemaMigrationConvertsManagingAppToManagedSpace() async throws {
        let fixture = try Fixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let initial = try await fixture.open()
        try await initial.close()

        let path = SQLiteLayout.accountDatabase(in: fixture.root, did: fixture.author).path
        try await installLegacySimpleSpaceAuthoritySchema(fixture)

        let migrated = try await fixture.open()
        try await withClosedAccountDatabase(migrated) { database in
            let authorization: AuthorizationContext = .accountOAuthForTesting(
                subject: fixture.author,
                scopes: ["atproto"]
            )
            let authority = DurableSimpleSpaceAuthority(lifecycleDatabase: database)
            // October 29 migration v29: both sides named the same managing
            // app, so the row becomes a managedspace policy.
            let migratedLookup = try await database.simpleSpace(
                fixture.space,
                authorization: authorization
            )
            let migratedState = try XCTUnwrap(migratedLookup)
            XCTAssertEqual(
                migratedState.space.configuration.policy,
                .managed(try ManagedSpacePolicy(managingApp: "did:web:manager.example"))
            )

            // updateSpace replaces the policy wholesale.
            let replaced = try await authority.update(
                space: fixture.space,
                configuration: SimpleSpaceConfiguration(
                    policy: .member(try MemberSpacePolicy(publicRead: true))
                ),
                authorization: authorization
            )
            XCTAssertEqual(
                replaced.space.configuration.policy,
                .member(try MemberSpacePolicy(publicRead: true))
            )
            XCTAssertEqual(replaced.space.configuration.readPolicy, .public)
            XCTAssertEqual(replaced.space.configuration.writePolicy, .memberList)
            XCTAssertNil(replaced.space.configuration.readManagingApp)
            XCTAssertNil(replaced.space.configuration.writeManagingApp)
        }

        let inspected = try await SQLiteConnection.open(storage: .file(path: path))
        do {
            let schemaRows = try await inspected.query(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'permissioned_simple_space_authorities'"
            )
            let schema = try XCTUnwrap(schemaRows.first?.column("sql")?.string)
            XCTAssertFalse(schema.contains("policy = 'managing-app' AND managing_app IS NOT NULL"))
            let marker = try await inspected.query(
                "SELECT 1 FROM permissioned_repository_migrations WHERE version = 23"
            )
            XCTAssertEqual(marker.count, 1)
            try await inspected.close()
        } catch {
            try? await inspected.close()
            throw error
        }
    }

    func testConcurrentFirstOpensSafelyShareLegacySimpleSpaceSchemaMigration() async throws {
        let fixture = try Fixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let initial = try await fixture.open()
        try await initial.close()
        try await installLegacySimpleSpaceAuthoritySchema(fixture)

        // These are independent SQLite connections, just as two processes
        // opening an authority database for the first time would be. Each
        // constructor runs all migrations before it returns.
        let root = fixture.root
        let did = fixture.author
        async let firstOpen = SQLiteAccountDatabase(dataDirectory: root, did: did)
        async let secondOpen = SQLiteAccountDatabase(dataDirectory: root, did: did)
        let (first, second) = try await (firstOpen, secondOpen)

        let authorization: AuthorizationContext = .accountOAuthForTesting(
            subject: fixture.author,
            scopes: ["atproto"]
        )
        try await withClosedAccountDatabases(first, second) { first, second in
            for database in [first, second] {
                let state = try await database.simpleSpace(
                    fixture.space,
                    authorization: authorization
                )
                XCTAssertEqual(state?.space.configuration.readPolicy, .managingApp)
                XCTAssertEqual(state?.space.configuration.writePolicy, .managingApp)
                XCTAssertEqual(
                    state?.space.configuration.readManagingApp,
                    "did:web:manager.example"
                )
                XCTAssertEqual(
                    state?.space.configuration.writeManagingApp,
                    "did:web:manager.example"
                )
                XCTAssertEqual(state?.space.members, [fixture.author: SimpleSpaceMember(did: fixture.author, read: true, write: true)])
            }
        }

        let path = SQLiteLayout.accountDatabase(in: fixture.root, did: fixture.author).path
        let inspected = try await SQLiteConnection.open(storage: .file(path: path))
        do {
            let marker = try await inspected.query(
                "SELECT 1 FROM permissioned_repository_migrations WHERE version = 23"
            )
            XCTAssertEqual(marker.count, 1)
            let stateRows = try await inspected.query(
                "SELECT read_policy, read_managing_app, write_policy, write_managing_app FROM permissioned_simple_space_authorities WHERE space_uri = ?",
                [.text(fixture.space.rawValue)]
            )
            XCTAssertEqual(stateRows.count, 1)
            XCTAssertEqual(stateRows.first?.column("read_policy")?.string, "managing-app")
            XCTAssertEqual(stateRows.first?.column("read_managing_app")?.string, "did:web:manager.example")
            XCTAssertEqual(stateRows.first?.column("write_policy")?.string, "managing-app")
            XCTAssertEqual(stateRows.first?.column("write_managing_app")?.string, "did:web:manager.example")
            let foreignKeys = try await inspected.query("PRAGMA foreign_key_check")
            XCTAssertTrue(foreignKeys.isEmpty)
            try await inspected.close()
        } catch {
            try? await inspected.close()
            throw error
        }
    }
    func testDurableSimpleSpaceIndependentReadWriteAccessAndMigration() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close(); try? FileManager.default.removeItem(at: fixture.root) } }

        let space = try SpaceURI(authority: fixture.author, spaceType: "app.bsky.feed.post", skey: "asymm-db")
        let authorization: AuthorizationContext = .accountOAuthForTesting(subject: fixture.author, scopes: ["atproto"])

        // 1. Create space with readPolicy: memberList, writePolicy: public
        _ = try await database.createSimpleSpace(
            space: space,
            owner: fixture.author,
            configuration: try SimpleSpaceConfiguration(readPolicy: .memberList, writePolicy: .public, appAccess: .open),
            authorization: authorization
        )

        let memberCarol = "did:plc:carol"
        // Carol not yet a member: can write under public writePolicy, cannot read under memberList readPolicy
        try await database.authorizeSimpleSpaceWrite(space: space, user: memberCarol)
        await XCTAssertThrowsErrorAsync(
            try await database.authorizeSimpleSpaceRead(
                space: space,
                user: memberCarol,
                clientID: nil,
                authorization: .accountOAuthForTesting(subject: memberCarol, scopes: ["atproto"])
            )
        )

        // 2. Duplicate DIDs are one mutation and the final member wins.
        _ = try await database.putSimpleSpaceMembers(
            space: space,
            members: [
                .init(did: memberCarol, read: false, write: true),
                .init(did: memberCarol, read: true, write: false),
            ],
            authorization: authorization
        )
        // Carol can now read
        try await database.authorizeSimpleSpaceRead(
            space: space,
            user: memberCarol,
            clientID: nil,
            authorization: .accountOAuthForTesting(subject: memberCarol, scopes: ["atproto"])
        )
        // A member's explicit write:false overrides publicWrite.
        await XCTAssertThrowsErrorAsync(
            try await database.authorizeSimpleSpaceWrite(space: space, user: memberCarol)
        )

        // 3. Update write policy to memberList: now Carol cannot write because Carol's write flag is false
        _ = try await database.updateSimpleSpace(
            space: space,
            configuration: try SimpleSpaceConfiguration(readPolicy: .memberList, writePolicy: .memberList, appAccess: .open),
            authorization: authorization
        )
        await XCTAssertThrowsErrorAsync(
            try await database.authorizeSimpleSpaceWrite(space: space, user: memberCarol)
        )

        // 4. Re-put member with read: false, write: true (replaces both flags)
        _ = try await database.putSimpleSpaceMembers(
            space: space,
            members: [.init(did: memberCarol, read: false, write: true)],
            authorization: authorization
        )
        // Now Carol can write
        try await database.authorizeSimpleSpaceWrite(space: space, user: memberCarol)
        // But cannot read
        await XCTAssertThrowsErrorAsync(
            try await database.authorizeSimpleSpaceRead(
                space: space,
                user: memberCarol,
                clientID: nil,
                authorization: .accountOAuthForTesting(subject: memberCarol, scopes: ["atproto"])
            )
        )

        // 5. Authority (owner) always admitted for both
        try await database.authorizeSimpleSpaceWrite(space: space, user: fixture.author)
        try await database.authorizeSimpleSpaceRead(
            space: space,
            user: fixture.author,
            clientID: nil,
            authorization: authorization
        )

        // 6. Explicit owner flags read: false, write: false are permitted,
        // authority authorization bypasses flags by identity and preserves admission.
        _ = try await database.putSimpleSpaceMembers(
            space: space,
            members: [.init(did: fixture.author, read: false, write: false)],
            authorization: authorization
        )
        try await database.close()

        let reopenedDatabase = try await fixture.open()
        defer { Task { try? await reopenedDatabase.close() } }
        let authority = try DurableSimpleSpaceAuthority(
            database: reopenedDatabase,
            credentialSecret: Data(repeating: 7, count: 32)
        )
        let ownerCredential = try await authority.issueReadCredential(
            space: space,
            user: fixture.author,
            clientID: nil,
            authorization: authorization
        )
        XCTAssertEqual(ownerCredential.credential.grant.subject, fixture.author)
        try await reopenedDatabase.authorizeSimpleSpaceWrite(space: space, user: fixture.author)
    }


    func testSQLiteCreatesOwnerOnlyRootDirectoriesAndDatabaseFiles() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSQLiteProtectedPathsTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let did = "did:plc:abcdefghijklmnopqrstuvwx"

        let control = try await SQLiteControlDatabase(dataDirectory: root)
        let account = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        defer {
            Task {
                try? await control.close()
                try? await account.close()
            }
        }

        let accountDatabase = SQLiteLayout.accountDatabase(in: root, did: did)
        XCTAssertEqual(try permissions(of: root), 0o700)
        XCTAssertEqual(try permissions(of: root.appending(path: "actors")), 0o700)
        XCTAssertEqual(try permissions(of: accountDatabase.deletingLastPathComponent()), 0o700)
        XCTAssertEqual(try permissions(of: SQLiteLayout.controlDatabase(in: root)), 0o600)
        XCTAssertEqual(try permissions(of: accountDatabase), 0o600)

        for database in [SQLiteLayout.controlDatabase(in: root), accountDatabase] {
            for suffix in ["-wal", "-shm"] {
                let sidecar = URL(fileURLWithPath: database.path + suffix)
                if FileManager.default.fileExists(atPath: sidecar.path) {
                    XCTAssertEqual(try permissions(of: sidecar), 0o600)
                }
            }
        }
    }

    func testSQLiteRejectsUnsafeOrSymlinkDataRootBeforeOpeningDatabases() async throws {
        let base = FileManager.default.temporaryDirectory
            .appending(path: "SwanSQLiteUnsafeRootTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: base) }
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o755)],
            ofItemAtPath: base.path
        )

        await XCTAssertThrowsErrorAsync(
            try await SQLiteControlDatabase(dataDirectory: base)
        ) { error in
            XCTAssertEqual(error as? SwanError, .unavailable("SQLite data directory is unavailable"))
        }
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: SQLiteLayout.controlDatabase(in: base).path
        ))

        let target = FileManager.default.temporaryDirectory
            .appending(path: "SwanSQLiteUnsafeRootTarget-\(UUID().uuidString)")
        let link = FileManager.default.temporaryDirectory
            .appending(path: "SwanSQLiteUnsafeRootLink-\(UUID().uuidString)")
        defer {
            try? FileManager.default.removeItem(at: target)
            try? FileManager.default.removeItem(at: link)
        }
        try FileManager.default.createDirectory(
            at: target,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: NSNumber(value: 0o700)]
        )
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        await XCTAssertThrowsErrorAsync(
            try await SQLiteControlDatabase(dataDirectory: link)
        ) { error in
            XCTAssertEqual(error as? SwanError, .unavailable("SQLite data directory is unavailable"))
        }
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: SQLiteLayout.controlDatabase(in: target).path
        ))
    }

    func testReadInFlightAcrossCloseWaitsForReadGate() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        _ = try await fixture.commitFirst(on: database)

        let readStarted = AsyncSignal()
        let releaseRead = AsyncSignal()
        let readFinished = AsyncSignal()

        let readTask = Task {
            try await database.withReadConnectionGate {
                await readStarted.signal()
                await releaseRead.wait()
                let rows = try await database.readConnection.query(
                    "SELECT COUNT(*) AS c FROM permissioned_repository_state"
                )
                await readFinished.signal()
                return rows.first?.column("c")?.integer
            }
        }

        await readStarted.wait()

        let closeTask = Task {
            try await database.close()
        }

        // Give closeTask a moment to arrive at the gates
        try await Task.sleep(nanoseconds: 20_000_000)

        // Release the read
        await releaseRead.signal()
        await readFinished.wait()

        let count = try await readTask.value
        XCTAssertEqual(count, 1)
        try await closeTask.value
    }

    func testConcurrentCommitDuringPublicRepositoryRecordCIDDoesNotCauseFalseCorruption() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPublicRecordCIDTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: NSNumber(value: 0o700)]
        )

        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let key = P256.Signing.PrivateKey()
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        defer { Task { try? await database.close() } }

        let genesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: "3jzfcijpj2z2a",
            signingKey: key
        )
        _ = try await database.installPublicRepositoryGenesis(
            genesis,
            signingPublicKey: key.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_750_000_000)
        )

        let path = try PublicRepositoryPath(
            collection: "app.bsky.feed.post",
            recordKey: "test-post"
        )
        let record = PublicRecord(["$type": .string("app.bsky.feed.post"), "text": .string("hello")])
        let preparedRecord = try PublicRepositoryRecordCodec.prepare(record, for: path)
        let recordCID = preparedRecord.cid
        // Initial query when no record exists returns nil
        let initial = try await database.publicRepositoryRecordCID(for: path)
        XCTAssertNil(initial)

        // Reserve and apply mutation on writer connection
        let loadedInitial = try await database.loadPublicRepositoryState()
        let initialPublicState = try XCTUnwrap(loadedInitial)
        let request = try PublicRepositoryMutationRequest(
            id: "req-1",
            canonicalDigest: Data(repeating: 0x42, count: 32),
            baseCommitCID: initialPublicState.commitCID
        )
        let outcome = try await database.reservePublicRepositoryRevision(
            request,
            wallClockMicroseconds: 1_750_000_000_000_000
        )
        guard case let .reserved(reservation) = outcome else {
            return XCTFail("expected reserved outcome")
        }
        let prepared = try await PublicRepositoryEngine.apply(
            repositoryDID: did,
            currentState: initialPublicState,
            blocks: database,
            revision: reservation.nextRevision,
            batch: try PublicRepositoryWriteBatch(
                writes: [.create(
                    path: path,
                    record: record
                )],
                expectedCommitCID: initialPublicState.commitCID
            ),
            signer: P256PublicRepositoryCommitSigner(privateKey: key)
        )
        _ = try await database.applyPublicRepositoryMutation(
            reservation: reservation,
            prepared: prepared
        )

        // Verify record CID on readConnection inside readTransaction
        let cid = try await database.publicRepositoryRecordCID(for: path)
        XCTAssertEqual(cid, recordCID)
    }

    func testSimpleSpaceMemberPageReadsAtomicSnapshotDuringConcurrentMutation() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close(); try? FileManager.default.removeItem(at: fixture.root) } }

        let space = try SpaceURI(
            authority: fixture.author,
            spaceType: "app.bsky.bookmarks",
            skey: "members-snapshot"
        )
        let authority = try DurableSimpleSpaceAuthority(
            database: database,
            credentialSecret: Data(repeating: 0xB5, count: 32)
        )
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        _ = try await authority.create(
            space: space,
            owner: fixture.author,
            configuration: try SimpleSpaceConfiguration(
                readPolicy: .memberList,
                writePolicy: .memberList,
                appAccess: .open
            ),
            authorization: .accountOAuthForTesting(subject: fixture.author, scopes: ["atproto"]),
            now: now
        )

        let memberAlice = "did:plc:alice00000000000000000001"
        _ = try await database.putSimpleSpaceMembers(
            space: space,
            members: [.init(did: memberAlice, read: true, write: true)],
            authorization: .accountOAuthForTesting(subject: fixture.author, scopes: ["atproto"]),
            now: now.addingTimeInterval(1)
        )

        let barrier = SnapshotReadBarrier()
        await database.installTestingHooks(
            SQLiteTestingHooks(
                afterSimpleSpaceMemberPageAuthorityRead: {
                    await barrier.pause()
                }
            )
        )

        // Launch read task on readConnection in background
        let readTask = Task {
            try await database.simpleSpaceMemberPage(
                space: space,
                limit: 100,
                cursor: nil,
                authorization: .accountOAuthForTesting(subject: fixture.author, scopes: ["atproto"])
            )
        }

        // Wait until readTask has opened its read transaction and read authority row
        await barrier.waitUntilPaused()

        // Concurrent mutation on writer connection adds memberBob and commits
        let memberBob = "did:plc:bob00000000000000000000002"
        _ = try await database.putSimpleSpaceMembers(
            space: space,
            members: [.init(did: memberBob, read: true, write: true)],
            authorization: .accountOAuthForTesting(subject: fixture.author, scopes: ["atproto"]),
            now: now.addingTimeInterval(2)
        )

        // Release readTask to continue reading members under readConnection's frozen snapshot
        await barrier.release()

        let page = try await readTask.value
        // Atomic snapshot MUST see [owner, alice] and MUST NOT see [bob]
        XCTAssertEqual(Set(page.members.map(\.did)), Set([fixture.author, memberAlice]))

        // Subsequent read (new transaction) sees all three
        let updatedPage = try await database.simpleSpaceMemberPage(
            space: space,
            limit: 100,
            cursor: nil,
            authorization: .accountOAuthForTesting(subject: fixture.author, scopes: ["atproto"])
        )
        XCTAssertEqual(Set(updatedPage.members.map(\.did)), Set([fixture.author, memberAlice, memberBob]))
    }

    func testValidatePortableRestoreStreamingReadsAtomicSnapshot() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close(); try? FileManager.default.removeItem(at: fixture.root) } }

        var ltHash = LtHash()
        ltHash.add(element: "\(fixture.first.collection)/\(fixture.first.rkey)/\(fixture.firstCID)")
        let recovery = VerifiedSpaceCARRecovery(
            wireRevision: try fixture.tid(0),
            records: [
                SpaceRecord(
                    uri: fixture.first,
                    value: fixture.firstValue,
                    cid: fixture.firstCID,
                    revision: 1
                ),
            ],
            ltHash: ltHash.serialized,
            commitment: ltHash.commitment
        )
        let repo = SQLitePortableRestoreRepository(
            space: fixture.space,
            author: fixture.author,
            recovery: recovery
        )
        try await database.restorePortableRepositories([repo])

        let metadata = SQLitePortableRestoreRepositoryMetadata(
            space: fixture.space,
            author: fixture.author,
            wireRevision: try fixture.tid(0),
            recordCount: 1,
            logicalRestoredByteCount: fixture.firstValue.count,
            ltHash: ltHash.serialized,
            commitment: ltHash.commitment
        )

        actor InTransactionObservation {
            var authorityRowCount: Int = -1
            func record(count: Int) {
                authorityRowCount = count
            }
            func count() -> Int { authorityRowCount }
        }
        let observation = InTransactionObservation()

        let barrier = SnapshotReadBarrier()
        await database.installTestingHooks(
            SQLiteTestingHooks(
                afterValidatePortableRestoreStateRead: {
                    await barrier.pause()
                },
                onValidatePortableRestoreStreamingTransaction: { conn in
                    let rows = try await conn.query(
                        "SELECT COUNT(*) AS c FROM permissioned_simple_space_authorities"
                    )
                    let c = rows.first?.column("c")?.integer ?? -1
                    await observation.record(count: Int(c))
                }
            )
        )

        // Launch streaming validation task on readConnection
        let validationTask = Task {
            try await database.validatePortableRestoreStreaming(repositories: [metadata])
        }

        // Wait until validationTask has read state on readConnection
        await barrier.waitUntilPaused()

        // Concurrent commit on writer connection (e.g. creating another simple space)
        let space = try SpaceURI(
            authority: fixture.author,
            spaceType: "app.bsky.bookmarks",
            skey: "concurrent-commit"
        )
        let authority = try DurableSimpleSpaceAuthority(
            database: database,
            credentialSecret: Data(repeating: 0xC3, count: 32)
        )
        _ = try await authority.create(
            space: space,
            owner: fixture.author,
            configuration: try SimpleSpaceConfiguration(
                readPolicy: .memberList,
                writePolicy: .memberList,
                appAccess: .open
            ),
            authorization: .accountOAuthForTesting(subject: fixture.author, scopes: ["atproto"]),
            now: Date(timeIntervalSince1970: 1_750_000_000)
        )

        // Release validationTask to finish validating values and closures on readConnection
        await barrier.release()

        // Must succeed without error under readConnection snapshot
        try await validationTask.value

        // Assert on the in-transaction observation: inside the validation transaction
        // on readConnection, permissioned_simple_space_authorities had 0 rows.
        let inTransactionCount = await observation.count()
        XCTAssertEqual(
            inTransactionCount,
            0,
            "in-flight validation transaction on readConnection must observe 0 authorities from its frozen pre-commit snapshot"
        )

        // Subsequent read on readConnection sees the newly committed space
        let hostedSpaces = try await database.hostedSpaces(
            spaceType: nil,
            authority: nil,
            cursor: nil,
            limit: 100
        )
        XCTAssertTrue(
            hostedSpaces.contains(where: { $0.space == space }),
            "subsequent read transaction must observe the newly committed space"
        )
    }

    func testCloseSurfacesReaderCloseFailureAndTracksClosedState() async throws {
        let fixture = try Fixture()
        let database = try await fixture.open()
        defer { Task { try? await database.close(); try? FileManager.default.removeItem(at: fixture.root) } }

        struct InjectedReaderCloseError: Error, Equatable {}

        actor AttemptCounter {
            var count = 0
            func increment() -> Int {
                count += 1
                return count
            }
            func value() -> Int { count }
        }
        let counter = AttemptCounter()

        // Install hook that injects a failure on the first reader-close attempt,
        // and succeeds on the second attempt while recording attempt count.
        await database.installTestingHooks(
            SQLiteTestingHooks(
                onReaderClose: {
                    let attempt = await counter.increment()
                    if attempt == 1 {
                        throw InjectedReaderCloseError()
                    }
                }
            )
        )

        // First close() must surface the injected reader error and not set isClosed = true
        var threwInjectedError = false
        do {
            try await database.close()
        } catch is InjectedReaderCloseError {
            threwInjectedError = true
        }
        XCTAssertTrue(threwInjectedError, "close() must propagate reader close failure")
        let firstAttempts = await counter.value()
        XCTAssertEqual(firstAttempts, 1, "first close() must attempt reader close exactly once")

        // Second close() must retry closing the live reader handle and increment the attempt count
        try await database.close()
        let secondAttempts = await counter.value()
        XCTAssertEqual(
            secondAttempts,
            2,
            "second close() must attempt closing the reader handle again instead of short-circuiting on isClosed"
        )

        // A third close() after successful closure is a harmless idempotent replay (isClosed is true)
        try await database.close()
        let thirdAttempts = await counter.value()
        XCTAssertEqual(
            thirdAttempts,
            2,
            "third close() after successful closure must be an idempotent no-op replay"
        )
    }
}

private extension SwanSQLiteTests {
    func controlRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanAccountControlTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o700)],
            ofItemAtPath: root.path
        )
        return root
    }

    func permissions(of url: URL) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        let mode = try XCTUnwrap(attributes[.posixPermissions] as? NSNumber)
        return mode.intValue & 0o777
    }

    func lockDownLegacySQLiteDatabase(
        _ database: URL,
        dataDirectory: URL
    ) throws {
        let root = dataDirectory.standardizedFileURL
        var directory = database.deletingLastPathComponent().standardizedFileURL
        while true {
            try FileManager.default.setAttributes(
                [.posixPermissions: NSNumber(value: 0o700)],
                ofItemAtPath: directory.path
            )
            // Foundation's Linux URL equality can retain distinct file URL
            // metadata even when the standardized paths are identical.
            // Compare the validated paths so this owner-only permission walk
            // terminates at the requested data root on every platform.
            if directory.path == root.path { break }
            let parent = directory.deletingLastPathComponent().standardizedFileURL
            guard parent.path.hasPrefix(root.path) else {
                throw SwanError.unavailable("test database escaped its root")
            }
            directory = parent
        }
        for suffix in ["", "-wal", "-shm"] {
            let file = URL(fileURLWithPath: database.path + suffix)
            guard FileManager.default.fileExists(atPath: file.path) else { continue }
            try FileManager.default.setAttributes(
                [.posixPermissions: NSNumber(value: 0o600)],
                ofItemAtPath: file.path
            )
        }
    }

    func controlRegistration(
        did: String,
        handle: String,
        createdAt: Date = Date(timeIntervalSince1970: 1_750_000_000)
    ) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
            rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
            createdAt: createdAt
        )
    }

    func controlCreateRace(
        first: SQLiteControlDatabase,
        second: SQLiteControlDatabase,
        firstRegistration: AccountControlRegistration,
        secondRegistration: AccountControlRegistration
    ) async -> (successes: Int, errors: [AccountControlStoreError]) {
        await withTaskGroup(
            of: Result<AccountControlAccount, any Error>.self,
            returning: (Int, [AccountControlStoreError]).self
        ) { group in
            group.addTask {
                do {
                    return .success(try await first.createAccount(firstRegistration))
                } catch {
                    return .failure(error)
                }
            }
            group.addTask {
                do {
                    return .success(try await second.createAccount(secondRegistration))
                } catch {
                    return .failure(error)
                }
            }
            let outcomes = await group.reduce(into: [Result<AccountControlAccount, any Error>]()) {
                $0.append($1)
            }
            return (
                outcomes.compactMap { try? $0.get() }.count,
                outcomes.compactMap { result in
                    guard case let .failure(error) = result else { return nil }
                    return error as? AccountControlStoreError
                }
            )
        }
    }
}

private struct Fixture {
    let root: URL
    let author = "did:plc:alice"
    let space: SpaceURI
    let first: SpaceRecordURI
    let second: SpaceRecordURI
    let third: SpaceRecordURI
    let missing: SpaceRecordURI
    let firstValue = Data([0xa1, 0x61, 0x61, 0x01])
    let secondValue = Data([0xa1, 0x61, 0x62, 0x02])
    let thirdValue = Data([0xa1, 0x61, 0x63, 0x03])
    var firstCID: String { CID.fromDAGCBOR(firstValue).string }
    var secondCID: String { CID.fromDAGCBOR(secondValue).string }
    var thirdCID: String { CID.fromDAGCBOR(thirdValue).string }

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSQLiteTests-\(UUID().uuidString)")
        space = try SpaceURI(
            authority: "did:plc:alice",
            spaceType: "app.bsky.bookmarks",
            skey: "self"
        )
        first = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.bsky.feed.post",
            rkey: "first"
        )
        second = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.bsky.feed.post",
            rkey: "second"
        )
        third = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.bsky.feed.post",
            rkey: "third"
        )
        missing = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.bsky.feed.post",
            rkey: "missing"
        )
    }

    func open(retention: Int = 10_000) async throws -> SQLiteAccountDatabase {
        try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: author,
            oplogRetention: retention
        )
    }

    func commitFirst(on database: SQLiteAccountDatabase) async throws -> PersistedRepositoryCommit {
        try await database.apply(
            space: space,
            author: author,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try tid(0),
            writes: [.put(uri: first, value: firstValue, cid: firstCID)],
        )
    }

    func tid(_ offset: Int) throws -> TID {
        let alphabet = Array("234567abcdefghijklmnopqrstuvwxyz")
        return try TID(tidString: "222222222222\(alphabet[offset])")
    }
}

private actor WireOplogMaterializationProbe {
    private var value = false

    func mark() {
        value = true
    }

    func didRun() -> Bool {
        value
    }
}

/// Installs the v1/v2 simple-space tables after the normal account migration
/// has created the rest of the account database. The only absent sentinel is
/// v3, so opening the database must replace this old CHECK constraint instead
/// of relying on fresh-create DDL.
private func installLegacySimpleSpaceAuthoritySchema(_ fixture: Fixture) async throws {
    let path = SQLiteLayout.accountDatabase(in: fixture.root, did: fixture.author).path
    let legacy = try await SQLiteConnection.open(storage: .file(path: path))
    do {
        _ = try await legacy.query("PRAGMA foreign_keys = OFF")
        for table in [
            "permissioned_simple_space_managing_app_decisions",
            "permissioned_simple_space_clients",
            "permissioned_simple_space_members",
            "permissioned_simple_space_authorities",
        ] {
            _ = try await legacy.query("DROP TABLE \(table)")
        }
        _ = try await legacy.query(
            """
            CREATE TABLE permissioned_simple_space_authorities (
                space_uri TEXT PRIMARY KEY,
                owner_did TEXT NOT NULL,
                policy TEXT NOT NULL CHECK(policy IN ('public', 'member-list', 'managing-app')),
                app_access TEXT NOT NULL CHECK(app_access IN ('open', 'allow-list')),
                managing_app TEXT,
                is_deleted INTEGER NOT NULL CHECK(is_deleted IN (0, 1)),
                revision INTEGER NOT NULL CHECK(revision > 0),
                created_at INTEGER NOT NULL CHECK(created_at >= 0),
                updated_at INTEGER NOT NULL CHECK(updated_at >= created_at),
                CHECK(
                    (policy = 'managing-app' AND managing_app IS NOT NULL AND length(managing_app) > 0)
                    OR (policy != 'managing-app' AND managing_app IS NULL)
                )
            )
            """
        )
        _ = try await legacy.query(
            """
            CREATE TABLE permissioned_simple_space_members (
                space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
                member_did TEXT NOT NULL,
                PRIMARY KEY(space_uri, member_did)
            )
            """
        )
        _ = try await legacy.query(
            """
            CREATE TABLE permissioned_simple_space_clients (
                space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
                client_id TEXT NOT NULL,
                PRIMARY KEY(space_uri, client_id)
            )
            """
        )
        _ = try await legacy.query(
            """
            CREATE TABLE permissioned_simple_space_managing_app_decisions (
                space_uri TEXT NOT NULL REFERENCES permissioned_simple_space_authorities(space_uri) ON DELETE CASCADE,
                user_did TEXT NOT NULL,
                PRIMARY KEY(space_uri, user_did)
            )
            """
        )
        _ = try await legacy.query(
            """
            INSERT INTO permissioned_simple_space_authorities(
                space_uri, owner_did, policy, app_access, managing_app,
                is_deleted, revision, created_at, updated_at
            ) VALUES (?, ?, 'managing-app', 'open', ?, 0, 1, 1, 1)
            """,
            [.text(fixture.space.rawValue), .text(fixture.author), .text("did:web:manager.example")]
        )
        _ = try await legacy.query(
            "INSERT INTO permissioned_simple_space_members(space_uri, member_did) VALUES (?, ?)",
            [.text(fixture.space.rawValue), .text(fixture.author)]
        )
        _ = try await legacy.query(
            "DELETE FROM permissioned_repository_migrations WHERE version IN (3, 23, 29)"
        )
        _ = try await legacy.query("PRAGMA foreign_keys = ON")
        try await legacy.close()
    } catch {
        try? await legacy.close()
        throw error
    }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ errorHandler: (any Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("expected error", file: file, line: line)
    } catch {
        errorHandler(error)
    }
}

private func withClosedAccountDatabase<T>(
    _ database: SQLiteAccountDatabase,
    body: (SQLiteAccountDatabase) async throws -> T
) async throws -> T {
    do {
        let value = try await body(database)
        try await database.close()
        return value
    } catch {
        try? await database.close()
        throw error
    }
}

private func withClosedAccountDatabases<T>(
    _ first: SQLiteAccountDatabase,
    _ second: SQLiteAccountDatabase,
    body: (SQLiteAccountDatabase, SQLiteAccountDatabase) async throws -> T
) async throws -> T {
    do {
        let value = try await body(first, second)
        try await first.close()
        try await second.close()
        return value
    } catch {
        try? await first.close()
        try? await second.close()
        throw error
    }
}

private struct InjectedTransactionFailure: Error {}
private struct InjectedOutboxTransportFailure: Error {}

private func outboxConfiguration(
    leaseDuration: TimeInterval = 10,
    idlePollInterval: TimeInterval = 1,
    initialFailureBackoff: TimeInterval = 1,
    maximumFailureBackoff: TimeInterval = 8
) throws -> PermissionedSpaceOutboxDeliveryConfiguration {
    try PermissionedSpaceOutboxDeliveryConfiguration(
        leaseDuration: leaseDuration,
        idlePollInterval: idlePollInterval,
        initialFailureBackoff: initialFailureBackoff,
        maximumFailureBackoff: maximumFailureBackoff
    )
}

private actor RecordingOutboxTransport: PermissionedSpaceOutboxTransport {
    private let database: SQLiteAccountDatabase?
    private var failuresRemaining: Int
    private var delivered: [PermissionedSpaceOutboxNotification] = []
    private var writeTransactionStates: [Bool] = []

    init(
        database: SQLiteAccountDatabase?,
        failuresRemaining: Int = 0
    ) {
        self.database = database
        self.failuresRemaining = failuresRemaining
    }

    func deliver(_ notification: PermissionedSpaceOutboxNotification) async throws {
        if let database {
            writeTransactionStates.append(await database.hasActiveWriteTransactionForTesting())
        }
        delivered.append(notification)
        if failuresRemaining > 0 {
            failuresRemaining -= 1
            throw InjectedOutboxTransportFailure()
        }
    }

    func notifications() -> [PermissionedSpaceOutboxNotification] { delivered }

    func observedWriteTransactions() -> [Bool] { writeTransactionStates }
}

private actor BlockingOutboxTransport: PermissionedSpaceOutboxTransport {
    private let barrier: OutboxDeliveryBarrier
    private var delivered: [PermissionedSpaceOutboxNotification] = []

    init(barrier: OutboxDeliveryBarrier) {
        self.barrier = barrier
    }

    func deliver(_ notification: PermissionedSpaceOutboxNotification) async throws {
        delivered.append(notification)
        await barrier.started()
        await barrier.waitForRelease()
    }

    func notifications() -> [PermissionedSpaceOutboxNotification] { delivered }
}

private actor LegacyBlobChunkCollector {
    private(set) var data = Data()
    private(set) var maximumChunk = 0

    func append(_ chunk: Data) {
        data.append(chunk)
        maximumChunk = max(maximumChunk, chunk.count)
    }
}

private actor OutboxDeliveryBarrier {
    private var didStart = false
    private var released = false
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseContinuation: CheckedContinuation<Void, Never>?

    func started() {
        didStart = true
        startWaiters.forEach { $0.resume() }
        startWaiters.removeAll()
    }

    func waitUntilStarted() async {
        guard !didStart else { return }
        await withCheckedContinuation { startWaiters.append($0) }
    }

    func waitForRelease() async {
        guard !released else { return }
        await withCheckedContinuation { releaseContinuation = $0 }
    }

    func release() {
        released = true
        releaseContinuation?.resume()
        releaseContinuation = nil
    }
}

private actor FailingApplyBarrier {
    private var hasFailed = false
    private var isPaused = false
    private var pauseWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseContinuation: CheckedContinuation<Void, Never>?

    func pauseThenFailOnce() async throws {
        guard !hasFailed else { return }
        hasFailed = true
        isPaused = true
        pauseWaiters.forEach { $0.resume() }
        pauseWaiters.removeAll()
        await withCheckedContinuation { releaseContinuation = $0 }
        throw InjectedTransactionFailure()
    }

    func waitUntilPaused() async {
        guard !isPaused else { return }
        await withCheckedContinuation { pauseWaiters.append($0) }
    }

    func release() {
        releaseContinuation?.resume()
        releaseContinuation = nil
    }
}

private actor BlobLifecycleBarrier {
    private var isPaused = false
    private var pauseWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseContinuation: CheckedContinuation<Void, Never>?

    func pause() async throws {
        guard !isPaused else { return }
        isPaused = true
        pauseWaiters.forEach { $0.resume() }
        pauseWaiters.removeAll()
        await withCheckedContinuation { releaseContinuation = $0 }
    }

    func waitUntilPaused() async {
        guard !isPaused else { return }
        await withCheckedContinuation { pauseWaiters.append($0) }
    }

    func release() {
        releaseContinuation?.resume()
        releaseContinuation = nil
    }
}

private actor SnapshotReadBarrier {
    private var isPaused = false
    private var pauseWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseContinuation: CheckedContinuation<Void, Never>?

    func pause() async {
        guard !isPaused else { return }
        isPaused = true
        pauseWaiters.forEach { $0.resume() }
        pauseWaiters.removeAll()
        await withCheckedContinuation { releaseContinuation = $0 }
    }

    func waitUntilPaused() async {
        guard !isPaused else { return }
        await withCheckedContinuation { pauseWaiters.append($0) }
    }

    func release() {
        releaseContinuation?.resume()
        releaseContinuation = nil
    }
}

private actor AsyncSignal {
    private var signaled = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func signal() {
        signaled = true
        waiters.forEach { $0.resume() }
        waiters.removeAll()
    }

    func wait() async {
        guard !signaled else { return }
        await withCheckedContinuation { waiters.append($0) }
    }
}
