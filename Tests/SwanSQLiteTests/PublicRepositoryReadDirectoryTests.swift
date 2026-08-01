import Crypto
import Foundation
import Hummingbird
import HTTPTypes
import Petrel
import SQLiteNIO
import SwanCore
import SwanHTTP
import SwanPublicRepository
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

final class PublicRepositoryReadDirectoryTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let handle = "alice.example.com"
    private let collection = "app.bsky.feed.post"

    func testPreopenedDirectoryReadsDIDHandlePagesAndStreamsStrictCAR() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let byDID = try await fixture.directory.describePublicRepository(
            selector: did
        )
        let byHandle = try await fixture.directory.describePublicRepository(
            selector: handle
        )
        XCTAssertEqual(byDID, byHandle)
        XCTAssertEqual(byDID?.collections, [collection])
        XCTAssertEqual(byDID?.state, fixture.state)

        let firstPath = try PublicRepositoryPath(
            collection: collection, recordKey: "one"
        )
        let maybeFirst = try await fixture.directory.publicRepositoryRecord(
            selector: handle,
            path: firstPath,
            expectedCID: nil
        )
        let first = try XCTUnwrap(maybeFirst)
        XCTAssertEqual(first.path, firstPath)
        XCTAssertNil(first.canonicalBytes.range(of: fixture.privateCollision))
        let mismatched = try await fixture.directory.publicRepositoryRecord(
            selector: did,
            path: firstPath,
            expectedCID: CID.fromDAGCBOR(Data("wrong".utf8))
        )
        XCTAssertNil(mismatched)

        let forward = try await fixture.directory.listPublicRepositoryRecords(
            selector: did,
            collection: collection,
            limit: 2,
            cursor: nil,
            reverse: false
        )
        XCTAssertEqual(forward.records.map(\.path.recordKey), ["two", "three"])
        XCTAssertEqual(forward.cursor, "three")
        let next = try await fixture.directory.listPublicRepositoryRecords(
            selector: handle,
            collection: collection,
            limit: 2,
            cursor: forward.cursor,
            reverse: false
        )
        XCTAssertEqual(next.records.map(\.path.recordKey), ["one"])
        XCTAssertEqual(next.cursor, "one")
        let terminal = try await fixture.directory.listPublicRepositoryRecords(
            selector: did,
            collection: collection,
            limit: 2,
            cursor: next.cursor,
            reverse: false
        )
        XCTAssertEqual(terminal.records, [])
        XCTAssertNil(terminal.cursor)
        let reverse = try await fixture.directory.listPublicRepositoryRecords(
            selector: did,
            collection: collection,
            limit: 2,
            cursor: nil,
            reverse: true
        )
        XCTAssertEqual(reverse.records.map(\.path.recordKey), ["one", "three"])
        XCTAssertFalse(
            forward.records.map(\.path.recordKey).contains("private-only")
        )

        let maybeCAR = try await fixture.directory.publicRepositoryCAR(
            selector: handle
        )
        let car = try XCTUnwrap(maybeCAR)
        let collector = PublicReadCARCollector()
        try await car.spool.stream(maximumChunkBytes: 1_024) {
            await collector.append($0)
        }
        XCTAssertTrue(car.spool.isCleanedUp)
        let maximumChunk = await collector.maximumChunk
        XCTAssertLessThanOrEqual(maximumChunk, 1_024)
        let carBytes = await collector.data
        XCTAssertNil(carBytes.range(of: fixture.privateCollision))
        XCTAssertNil(carBytes.range(of: fixture.privateOnly))
        let imported = try await PublicRepositoryCAR.importRepository(
            from: PublicReadCARSource(carBytes),
            verifier: P256PublicRepositoryCommitVerifier(
                publicKey: fixture.key.publicKey
            )
        )
        XCTAssertEqual(imported.state, fixture.state)
        XCTAssertEqual(imported.repository.leaves.count, 3)

        try await fixture.directory.close()
        try await fixture.control.close()
    }

    func testPinnedTypeScriptListRecordsPaginationFixture() throws {
        let fixtureURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
            .appending(
                path: "fixtures/permissioned-data-0016-2026-07-03/public-list-records-pagination.json"
            )
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL))
                as? [String: Any]
        )
        XCTAssertEqual(
            object["referenceCommit"] as? String,
            "3f6c96d5d2d25438bd40fa89d6ecc37865f8e354"
        )
        let cases = try XCTUnwrap(object["cases"] as? [[String: Any]])
        XCTAssertEqual(cases.count, 4)
        XCTAssertEqual(cases[0]["records"] as? [String], ["two", "three"])
        XCTAssertEqual(cases[0]["outputCursor"] as? String, "three")
        XCTAssertEqual(cases[1]["records"] as? [String], ["one"])
        XCTAssertEqual(cases[2]["records"] as? [String], [])
        XCTAssertTrue(cases[2]["outputCursor"] is NSNull)
        XCTAssertEqual(cases[3]["records"] as? [String], ["one", "three"])
    }

    func testSpoolAdmissionBoundsGlobalAndPerAccountReservations() throws {
        let admission = try PublicRepositorySpoolAdmission(
            maximumGlobalBytes: 20,
            maximumPerAccountBytes: 10
        )
        let alice = "did:plc:abcdefghijklmnopqrstuvwx"
        let bob = "did:plc:zyxwvutsrqponmlkjihgfedc"
        let first = try XCTUnwrap(
            admission.reserve(accountDID: alice, maximumBytes: 10)
        )
        XCTAssertNil(admission.reserve(accountDID: alice, maximumBytes: 1))
        let second = try XCTUnwrap(
            admission.reserve(accountDID: bob, maximumBytes: 10)
        )
        XCTAssertNil(admission.reserve(accountDID: bob, maximumBytes: 1))
        XCTAssertEqual(
            admission.snapshot,
            .init(
                reservedBytes: 20,
                activeLeases: 2,
                reservedBytesByAccount: [alice: 10, bob: 10]
            )
        )
        first.release()
        XCTAssertEqual(admission.snapshot.reservedBytes, 10)
        second.release()
        XCTAssertEqual(admission.snapshot.activeLeases, 0)
    }

    func testDirectoryRejectsSecondSlowConsumerAndReleasesOnCleanup() async throws {
        let maximum = PublicRepositoryLimits.standard.maximumCARBytes
        let admission = try PublicRepositorySpoolAdmission(
            maximumGlobalBytes: maximum,
            maximumPerAccountBytes: maximum
        )
        let fixture = try await makeFixture(admission: admission)
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let maybeFirst = try await fixture.directory.publicRepositoryCAR(
            selector: did
        )
        let first = try XCTUnwrap(maybeFirst)
        XCTAssertEqual(admission.snapshot.activeLeases, 1)
        await XCTAssertThrowsPublicReadUnavailable(
            try await fixture.directory.publicRepositoryCAR(selector: did)
        )
        XCTAssertEqual(admission.snapshot.activeLeases, 1)
        first.spool.cleanup()
        XCTAssertEqual(admission.snapshot.activeLeases, 0)
        let maybeNext = try await fixture.directory.publicRepositoryCAR(
            selector: did
        )
        let next = try XCTUnwrap(maybeNext)
        next.spool.cleanup()
        XCTAssertEqual(admission.snapshot.activeLeases, 0)
        try await fixture.directory.close()
        try await fixture.control.close()
    }

    func testBoundedExportRejectsCorruptIndexWithoutPublishingCAR() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let store = await fixture.directory.preopenedPublicMutationStore(
            did: did
        )
        let database = try XCTUnwrap(store as? SQLiteAccountDatabase)
        try await corruptPublicProjectionIndex(
            connection: database.connection,
            collection: collection,
            recordKey: "one",
            replacementCID: fixture.state.dataCID.string
        )
        await XCTAssertThrowsPublicReadUnavailable(
            try await fixture.directory.publicRepositoryCAR(selector: did)
        )
        try await fixture.directory.close()
        try await fixture.control.close()
    }

    // Production mutation caught: `bootstrap` returns an active preopened
    // database without first calling `verifyPublicRepositoryProjection()`.
    func testBootstrapRejectsCorruptPublicProjectionBeforeDirectoryActivation() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        try await fixture.directory.close()

        let raw = try await SQLiteConnection.open(
            storage: .file(
                path: SQLiteLayout.accountDatabase(
                    in: fixture.root, did: did
                ).path
            )
        )
        do {
            try await corruptPublicProjectionIndex(
                connection: raw,
                collection: collection,
                recordKey: "one",
                replacementCID: fixture.state.dataCID.string
            )
            try await raw.close()
        } catch {
            try? await raw.close()
            throw error
        }

        do {
            let unexpected = try await SQLitePreMigratedAccountDirectory
                .bootstrap(
                    dataDirectory: fixture.root,
                    controlStore: fixture.control,
                    publicIdentityVerifier: TestPublicPLCGenesisVerifier(
                        operationCID: fixture.genesisOperationCID
                    )
                )
            try? await unexpected.close()
            XCTFail(
                "corrupt public projection must fail before the directory becomes active"
            )
        } catch let error as SwanError {
            guard case .unavailable = error else {
                XCTFail("expected unavailable, got \(error)")
                try await fixture.control.close()
                return
            }
        } catch {
            XCTFail("expected SwanError.unavailable, got \(error)")
        }

        try await fixture.control.close()
    }

    // Production mutation caught: `admitActivatedAccount` stores the opened
    // database in `databases[did]` without first validating its public
    // repository projection.
    func testActivatedAccountAdmissionRejectsCorruptPublicProjectionBeforeExposure() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        try await fixture.directory.close()
        _ = try await fixture.control.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_020)
        )
        let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: fixture.root,
            controlStore: fixture.control,
            publicIdentityVerifier: TestPublicPLCGenesisVerifier(
                operationCID: fixture.genesisOperationCID
            )
        )
        let database = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root, did: did
        )
        try await corruptPublicProjectionIndex(
            connection: database.connection,
            collection: collection,
            recordKey: "one",
            replacementCID: fixture.state.dataCID.string
        )
        _ = try await fixture.control.transitionStatus(
            did: did,
            to: .active,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_021)
        )

        await XCTAssertThrowsSwanUnavailable(
            try await directory.admitActivatedAccount(
                SQLiteActivatedAccountAdmission(did: did, database: database)
            )
        )
        let exposed = await directory.preopenedPublicMutationStore(did: did)
        XCTAssertNil(exposed)

        try await directory.close()
        try? await database.close()
        try await fixture.control.close()
    }

    // Production mutation caught: `readPublicRepositoryRecord` or the
    // description projection used by the JSON handler uses the write-reserving
    // `transaction` helper (`BEGIN IMMEDIATE`) after admission.
    func testBoundedPublicRecordReadProceedsWhileSQLiteWriterIsReserved() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let store = await fixture.directory.preopenedPublicMutationStore(
            did: did
        )
        let database = try XCTUnwrap(store as? SQLiteAccountDatabase)
        _ = try await database.connection.query("PRAGMA busy_timeout=0")

        do {
            try await withReservedSQLiteWriter(
                databaseURL: SQLiteLayout.accountDatabase(
                    in: fixture.root, did: did
                )
            ) {
                let path = try PublicRepositoryPath(
                    collection: collection, recordKey: "one"
                )
                let maybeRecord = try await fixture.directory.publicRepositoryRecord(
                    selector: did,
                    path: path,
                    expectedCID: nil
                )
                let record = try XCTUnwrap(maybeRecord)
                XCTAssertEqual(record.path, path)
                let maybeDescription = try await fixture.directory
                    .describePublicRepository(
                        selector: did
                    )
                let description = try XCTUnwrap(maybeDescription)
                XCTAssertEqual(description.did, did)
            }
        } catch {
            XCTFail(
                "bounded public read attempted to reserve the SQLite writer: \(error)"
            )
        }

        try await fixture.directory.close()
        try await fixture.control.close()
    }

    // Production mutation caught: listRecords selects the next record BLOB
    // before checking whether its scalar length would exceed the aggregate
    // anonymous-response budget.
    func testListRecordsDoesNotMaterializeBodyBeyondAggregateBudget() async throws {
        let fixture = try await makeFixture(
            publicRecordKeys: ["one", "two", "three", "four", "five"],
            publicRecordTextPaddingBytes: 900_000
        )
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let store = await fixture.directory.preopenedPublicMutationStore(
            did: did
        )
        let database = try XCTUnwrap(store as? SQLiteAccountDatabase)
        let maybeAccount = try await fixture.control.account(did: did)
        let account = try XCTUnwrap(maybeAccount)
        let generation = try await database.admitPublicRepositoryGeneration(
            account: account,
            identityVerifier: TestPublicPLCGenesisVerifier(
                operationCID: fixture.genesisOperationCID
            )
        )

        let cleanRead = try await database.readPublicRepositoryRecords(
            collection: collection,
            limit: 100,
            cursor: nil,
            reverse: false,
            generation: generation
        )
        XCTAssertEqual(cleanRead.page.records.count, 4)
        let emittedPaths = Set(cleanRead.page.records.map(\.path))
        let allPaths = try Set(
            ["one", "two", "three", "four", "five"].map {
                try PublicRepositoryPath(
                    collection: collection, recordKey: $0
                )
            }
        )
        let excludedPaths = allPaths.subtracting(emittedPaths)
        XCTAssertEqual(excludedPaths.count, 1)
        let excludedPath = try XCTUnwrap(excludedPaths.first)
        let maybeExcludedCID =
            try await database.publicRepositoryRecordCID(for: excludedPath)
        let excludedCID = try XCTUnwrap(maybeExcludedCID)
        let maybeExcludedBytes = try await database.block(for: excludedCID)
        let excludedBytes = try XCTUnwrap(maybeExcludedBytes)

        // Preserve SQLite LENGTH(bytes), but make selecting this value fail
        // closed as a canonical block. A correct reader never selects it
        // because the preceding four bodies already consume the page budget.
        _ = try await database.connection.query(
            """
            UPDATE public_repository_blocks
            SET bytes = ?
            WHERE cid = ?
            """,
            [
                .text(String(repeating: "x", count: excludedBytes.count)),
                .text(excludedCID.string),
            ]
        )

        let boundedRead = try await database.readPublicRepositoryRecords(
            collection: collection,
            limit: 100,
            cursor: nil,
            reverse: false,
            generation: generation
        )
        XCTAssertEqual(
            boundedRead.page.records.map(\.path),
            cleanRead.page.records.map(\.path)
        )
        XCTAssertLessThanOrEqual(
            boundedRead.page.records.reduce(0) {
                $0 + $1.canonicalBytes.count
            },
            PublicRepositoryJSONReadLimits.maximumAggregateRecordBlockBytes
        )

        try await fixture.directory.close()
        try await fixture.control.close()
    }

    // Production mutation caught: the scalar-length preflight was present
    // for list pages but not the single-record JSON path. A corrupt block
    // larger than the public read budget must fail before its BLOB is selected
    // and decoded.
    func testSingleRecordReadRejectsOverBudgetBodyBeforeDecode() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let store = await fixture.directory.preopenedPublicMutationStore(
            did: did
        )
        let database = try XCTUnwrap(store as? SQLiteAccountDatabase)
        let maybeAccount = try await fixture.control.account(did: did)
        let account = try XCTUnwrap(maybeAccount)
        let generation = try await database.admitPublicRepositoryGeneration(
            account: account,
            identityVerifier: TestPublicPLCGenesisVerifier(
                operationCID: fixture.genesisOperationCID
            )
        )
        let path = try PublicRepositoryPath(
            collection: collection, recordKey: "one"
        )
        let maybeCID = try await database.publicRepositoryRecordCID(for: path)
        let cid = try XCTUnwrap(maybeCID)
        _ = try await database.connection.query(
            """
            UPDATE public_repository_blocks
            SET bytes = ?
            WHERE cid = ?
            """,
            [
                .text(String(
                    repeating: "x",
                    count: PublicRepositoryLimits.standard
                        .maximumRecordBlockBytes + 1
                )),
                .text(cid.string),
            ]
        )

        await XCTAssertThrowsPublicReadUnavailable(
            try await database.readPublicRepositoryRecord(
                path: path,
                expectedCID: nil,
                generation: generation
            )
        )

        try await fixture.directory.close()
        try await fixture.control.close()
    }

    func testDescribeRepoFailsClosedForTamperedGenesisAndIntentCID() async throws {
        // Startup admission authenticates both the signed PLC genesis facts
        // and the durable preparation intent before publishing a directory.
        // Tampering either value must therefore fail before a request can
        // observe a half-admitted account.
        for tamper in ["signature", "intent"] {
            do {
                _ = try await makeFixture(
                    tamperJournalSignature: tamper == "signature",
                    tamperIntentCID: tamper == "intent"
                )
                XCTFail(
                    "tampered PLC \(tamper) must be rejected during bootstrap"
                )
            } catch {
                guard let swanError = error as? SwanError else {
                    XCTFail("expected SwanError.unavailable, got \(error)")
                    continue
                }
                guard case .unavailable = swanError else {
                    XCTFail("expected unavailable, got \(swanError)")
                    continue
                }
            }
        }
    }

    func testPublicReadAdmissionAndBlobPromotionRejectOversizedIndexBeforeWalk() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let store = await fixture.directory.preopenedPublicMutationStore(did: did)
            let database = try XCTUnwrap(store as? SQLiteAccountDatabase)
            let firstPath = try PublicRepositoryPath(
                collection: collection, recordKey: "one"
            )
            let maybeFirstCID = try await database.publicRepositoryRecordCID(
                for: firstPath
            )
            let firstCID = try XCTUnwrap(maybeFirstCID)
            let raw = try await SQLiteConnection.open(
                storage: .file(
                    path: SQLiteLayout.accountDatabase(
                        in: fixture.root, did: did
                    ).path
                )
            )
            do {
                // Ten decimal digits crossed five independent CTE dimensions,
                // producing 100,000 valid index paths without constructing a
                // large Swift array. The final row crosses the admission bound.
                _ = try await raw.query(
                    """
                    WITH digit(n) AS (
                        VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9)
                    ),
                    numbers(n) AS (
                        SELECT a.n * 10000 + b.n * 1000 + c.n * 100
                            + d.n * 10 + e.n
                        FROM digit a
                        CROSS JOIN digit b
                        CROSS JOIN digit c
                        CROSS JOIN digit d
                        CROSS JOIN digit e
                    )
                    INSERT INTO public_repository_record_index(
                        collection, rkey, record_cid
                    )
                    SELECT 'app.bsky.feed.post', printf('%05d', n), ?
                    FROM numbers
                    UNION ALL
                    SELECT 'app.bsky.feed.post', '100000', ?
                    """,
                    [.text(firstCID.string), .text(firstCID.string)]
                )
                try await raw.close()
            } catch {
                try? await raw.close()
                throw error
            }

            do {
                _ = try await database.publicRepositoryBlobCIDs()
                XCTFail("oversized blob-promotion index must fail before decoding")
            } catch let error as PublicRepositoryReadError {
                XCTAssertEqual(error, .resourceLimitExceeded)
            }

            let maybeAccount = try await fixture.control.account(did: did)
            let account = try XCTUnwrap(maybeAccount)
            do {
                _ = try await database.admitPublicRepositoryGeneration(
                    account: account,
                    identityVerifier: TestPublicPLCGenesisVerifier(
                        operationCID: fixture.genesisOperationCID
                    )
                )
                XCTFail("oversized public-read index must fail before projection validation")
            } catch let error as PublicRepositoryReadError {
                XCTAssertEqual(error, .resourceLimitExceeded)
            }

            try await fixture.directory.close()
            try await fixture.control.close()
        } catch {
            try? await fixture.directory.close()
            try? await fixture.control.close()
            throw error
        }

    }

    func testPublicRepositoryBlobCIDsExtractsTypedRawLinksFromInstalledRecords() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root, did: did
        )
        let payload = Data("imported-public-blob".utf8)
        let reference = try await database.putStreaming(
            namespace: .public,
            mimeType: "application/octet-stream",
            maximumBytes: PublicRepositoryLimits.requiredStreamingCARBytes
        ) { sink in
            try await sink(payload)
        }
        let path = try PublicRepositoryPath(
            collection: collection, recordKey: "typed-blob"
        )
        let record: PublicRecord = [
            "$type": .string(collection),
            "blob": .object([
                "$type": .string("blob"),
                "ref": .link(try CID.parse(reference.cid)),
                "mimeType": .string("application/octet-stream"),
                "size": .integer(payload.count),
            ]),
        ]
        let maybeCurrent = try await database.loadPublicRepositoryState()
        let current = try XCTUnwrap(maybeCurrent)
        let request = try PublicRepositoryMutationRequest(
            id: "typed-blob-read-projection",
            canonicalDigest: Data(repeating: 0x74, count: 32),
            baseCommitCID: current.commitCID
        )
        guard case let .reserved(reservation) = try await database
            .reservePublicRepositoryRevision(
                request, wallClockMicroseconds: 1_750_000_002_000_000
            ) else {
            return XCTFail("typed blob projection reservation should be fresh")
        }
        let prepared = try await PublicRepositoryEngine.apply(
            repositoryDID: did,
            currentState: current,
            blocks: database,
            revision: reservation.nextRevision,
            batch: try PublicRepositoryWriteBatch(
                writes: [.create(path: path, record: record)],
                expectedCommitCID: current.commitCID
            ),
            signer: P256PublicRepositoryCommitSigner(privateKey: fixture.key)
        )
        _ = try await database.applyPublicRepositoryMutation(
            reservation: reservation, prepared: prepared
        )

        let cids = try await database.publicRepositoryBlobCIDs()
        XCTAssertEqual(cids, [try CID.parse(reference.cid)])
        let isReachable = try await database.publicBlobExists(cid: reference.cid)
        XCTAssertTrue(isReachable)
        try await database.close()
        try await fixture.directory.close()
        try await fixture.control.close()
    }

    func testOptIn256MiBProductionDirectoryGetRepoHasBoundedRSS() async throws {
        guard ProcessInfo.processInfo.environment[
            "SWAN_RUN_256MIB_PUBLIC_GET_REPO"
        ] == "1" else {
            throw XCTSkip(
                "set SWAN_RUN_256MIB_PUBLIC_GET_REPO=1 for the 256 MiB public export gate"
            )
        }
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        try await fixture.directory.close()
        let database = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root, did: did
        )
        let maybeState = try await database.loadPublicRepositoryState()
        var state = try XCTUnwrap(maybeState)
        let payload = Data(repeating: 0x5a, count: 900_000)
        for index in 0..<300 {
            let request = try PublicRepositoryMutationRequest(
                id: "large-public-\(index)",
                canonicalDigest: Data(
                    SHA256.hash(data: Data("large-public-\(index)".utf8))
                ),
                baseCommitCID: state.commitCID
            )
            guard case let .reserved(reservation) =
                    try await database.reservePublicRepositoryRevision(
                        request,
                        wallClockMicroseconds: 1_760_000_000_000_000
                            + UInt64(index)
                    ) else {
                return XCTFail("expected revision reservation")
            }
            let path = try PublicRepositoryPath(
                collection: collection,
                recordKey: String(format: "large-%04d", index)
            )
            let prepared = try await PublicRepositoryEngine.apply(
                repositoryDID: did,
                currentState: state,
                blocks: database,
                revision: reservation.nextRevision,
                batch: PublicRepositoryWriteBatch(
                    writes: [
                        .create(
                            path: path,
                            record: [
                                "$type": .string(collection),
                                "index": .integer(index),
                                "payload": .bytes(payload),
                            ]
                        ),
                    ],
                    expectedCommitCID: state.commitCID
                ),
                signer: P256PublicRepositoryCommitSigner(
                    privateKey: fixture.key
                )
            )
            state = try await database.applyPublicRepositoryMutation(
                reservation: reservation, prepared: prepared
            ).state
        }
        try await database.close()
        let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: fixture.root,
            controlStore: fixture.control,
            publicIdentityVerifier: TestPublicPLCGenesisVerifier(
                operationCID: fixture.genesisOperationCID
            )
        )
        let baseline = currentResidentBytes()
        let sampler = PublicReadRSSSampler(initial: baseline)
        let samplerTask = Task {
            while !Task.isCancelled {
                await sampler.sample(currentResidentBytes())
                try? await Task.sleep(for: .milliseconds(2))
            }
        }
        let maybeCAR = try await directory.publicRepositoryCAR(selector: did)
        let car = try XCTUnwrap(maybeCAR)
        let response = publicRepositoryCARHTTPResponse(car)
        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(
            response.headers[.contentType], "application/vnd.ipld.car"
        )
        let writer = PublicReadHTTPDiscardWriter()
        try await response.body.write(writer)
        samplerTask.cancel()
        _ = await samplerTask.result
        let streamedBytes = writer.byteCount
        XCTAssertGreaterThanOrEqual(
            streamedBytes,
            PublicRepositoryLimits.requiredStreamingCARBytes
        )
        XCTAssertLessThanOrEqual(
            writer.maximumChunkBytes,
            PublicRepositoryCARSpool.maximumChunkBytes
        )
        XCTAssertTrue(writer.finished)
        let sampledPeak = await sampler.peak
        XCTAssertLessThan(
            max(0, sampledPeak - baseline),
            128 * 1_024 * 1_024,
            "production directory-to-HTTP export must stay bounded during preparation and drain"
        )
        try await directory.close()
        try await fixture.control.close()
    }

    func testLifecyclePathClosureAndCancelledSpoolFailClosedWithoutReopen() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let maybeCAR = try await fixture.directory.publicRepositoryCAR(
            selector: did
        )
        let car = try XCTUnwrap(maybeCAR)
        do {
            try await car.spool.stream { _ in
                throw CancellationError()
            }
            XCTFail("expected cancellation")
        } catch is CancellationError {}
        XCTAssertTrue(car.spool.isCleanedUp)

        _ = try await fixture.control.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_010)
        )
        let maybeInactive = try await fixture.directory.publicRepositoryStatus(
            selector: handle
        )
        let inactive = try XCTUnwrap(maybeInactive)
        XCTAssertEqual(inactive.status, .deactivated)
        XCTAssertNil(inactive.revision)
        let inactiveCAR = try await fixture.directory.publicRepositoryCAR(
            selector: did
        )
        XCTAssertNil(inactiveCAR)

        _ = try await fixture.control.transitionStatus(
            did: did,
            to: .active,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_011)
        )
        let databaseURL = SQLiteLayout.accountDatabase(
            in: fixture.root, did: did
        )
        try FileManager.default.removeItem(at: databaseURL)
        let regularReplacement = Data("must-not-be-opened-as-the-database".utf8)
        try regularReplacement.write(to: databaseURL)
        await XCTAssertThrowsPublicReadUnavailable(
            try await fixture.directory.describePublicRepository(selector: did)
        )
        XCTAssertEqual(try Data(contentsOf: databaseURL), regularReplacement)

        try FileManager.default.removeItem(at: databaseURL)
        let outside = fixture.root.appending(path: "outside-replacement.sqlite")
        let outsideMarker = Data("must-not-be-opened".utf8)
        try outsideMarker.write(to: outside)
        try FileManager.default.createSymbolicLink(
            at: databaseURL,
            withDestinationURL: outside
        )
        await XCTAssertThrowsPublicReadUnavailable(
            try await fixture.directory.describePublicRepository(selector: did)
        )
        XCTAssertEqual(try Data(contentsOf: outside), outsideMarker)
        XCTAssertFalse(FileManager.default.fileExists(atPath: outside.path + "-wal"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: outside.path + "-shm"))
        let replacementValues = try databaseURL.resourceValues(
            forKeys: [.isSymbolicLinkKey]
        )
        XCTAssertEqual(replacementValues.isSymbolicLink, true)

        try await fixture.directory.close()
        await XCTAssertThrowsPublicReadUnavailable(
            try await fixture.directory.publicRepositoryStatus(selector: did)
        )
        try await fixture.control.close()
    }

    func testReactivationRefreshesPublicReadGenerationBeforeServingPublicData() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        _ = try await fixture.control.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_030)
        )
        let maybeInactive = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        let inactive = try XCTUnwrap(maybeInactive)
        XCTAssertEqual(inactive.status, .deactivated)
        XCTAssertNil(inactive.revision)

        _ = try await fixture.control.transitionStatus(
            did: did,
            to: .active,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_031)
        )

        // Reactivation changes the control-row revision/updatedAt while the
        // SQLite actor stays preopened. The first public request must
        // re-admit that existing database and publish a new generation.
        let maybeStatus = try await fixture.directory.publicRepositoryStatus(
            selector: did
        )
        let status = try XCTUnwrap(maybeStatus)
        XCTAssertEqual(status.status, .active)
        XCTAssertEqual(status.revision, fixture.state.revision)

        let maybeDescription = try await fixture.directory
            .describePublicRepository(selector: did)
        let description = try XCTUnwrap(maybeDescription)
        XCTAssertEqual(description.state, fixture.state)

        let path = try PublicRepositoryPath(
            collection: collection,
            recordKey: "one"
        )
        let maybeRecord = try await fixture.directory.publicRepositoryRecord(
            selector: did,
            path: path,
            expectedCID: nil
        )
        let record = try XCTUnwrap(maybeRecord)
        XCTAssertEqual(record.path, path)

        let maybeCAR = try await fixture.directory.publicRepositoryCAR(
            selector: did
        )
        let car = try XCTUnwrap(maybeCAR)
        let collector = PublicReadCARCollector()
        try await car.spool.stream { chunk in
            await collector.append(chunk)
        }
        XCTAssertTrue(car.spool.isCleanedUp)
        let carBytes = await collector.data
        let imported = try await PublicRepositoryCAR.importRepository(
            from: PublicReadCARSource(carBytes),
            verifier: P256PublicRepositoryCommitVerifier(
                publicKey: fixture.key.publicKey
            )
        )
        XCTAssertEqual(imported.state, fixture.state)

        try await fixture.directory.close()
        try await fixture.control.close()
    }

    private func makeFixture(
        admission: PublicRepositorySpoolAdmission? = nil,
        tamperJournalSignature: Bool = false,
        tamperIntentCID: Bool = false,
        publicRecordKeys: [String] = ["one", "two", "three"],
        publicRecordTextPaddingBytes: Int = 0
    ) async throws -> (
        root: URL,
        control: SQLiteControlDatabase,
        directory: SQLitePreMigratedAccountDirectory,
        key: P256.Signing.PrivateKey,
        state: PublicRepositoryState,
        genesisOperationCID: String,
        privateCollision: Data,
        privateOnly: Data
    ) {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPublicReadDirectoryTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: true
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: root.path
        )
        let key = P256.Signing.PrivateKey()
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root, did: did
        )
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
        let maybeInitial = try await database.loadPublicRepositoryState()
        let initial = try XCTUnwrap(maybeInitial)
        let writes: [PublicRepositoryWrite] = try publicRecordKeys.map {
            let path = try PublicRepositoryPath(
                collection: collection, recordKey: $0
            )
            let text = publicRecordTextPaddingBytes == 0
                ? "public-\($0)"
                : "public-\($0)-"
                    + String(
                        repeating: "x",
                        count: publicRecordTextPaddingBytes
                    )
            return .create(
                path: path,
                record: [
                    "$type": .string(collection),
                    "text": .string(text),
                ]
            )
        }
        // Commit one record at a time so the hostile large-record fixture can
        // exceed the read-page budget without violating the pinned 2 MB
        // relevant-block limit on any individual mutation.
        var currentState = initial
        for (index, write) in writes.enumerated() {
            let request = try PublicRepositoryMutationRequest(
                id: "public-read-fixture-\(index)",
                canonicalDigest: Data(
                    repeating: UInt8(truncatingIfNeeded: 0x43 + index),
                    count: 32
                ),
                baseCommitCID: currentState.commitCID
            )
            guard case let .reserved(reservation) =
                try await database.reservePublicRepositoryRevision(
                    request,
                    wallClockMicroseconds:
                        1_750_000_001_000_000 + UInt64(index)
                ) else {
                throw PublicRepositoryReadError.unavailable
            }
            let prepared = try await PublicRepositoryEngine.apply(
                repositoryDID: did,
                currentState: currentState,
                blocks: database,
                revision: reservation.nextRevision,
                batch: try PublicRepositoryWriteBatch(
                    writes: [write],
                    expectedCommitCID: currentState.commitCID
                ),
                signer: P256PublicRepositoryCommitSigner(privateKey: key)
            )
            _ = try await database.applyPublicRepositoryMutation(
                reservation: reservation, prepared: prepared
            )
            currentState = prepared.state
        }
        let privateCollision = try DAGCBOR.encodeValue(
            OrderedCBORMap(entries: [
                (key: "secret", value: "permissioned-private-one"),
            ])
        )
        let privateOnly = try DAGCBOR.encodeValue(
            OrderedCBORMap(entries: [
                (key: "secret", value: "permissioned-private-only"),
            ])
        )
        let privateSpace = try SpaceURI(
            authority: did,
            spaceType: "app.bsky.bookmarks",
            skey: "private"
        )
        let privateCollisionURI = try SpaceRecordURI(
            space: privateSpace,
            author: did,
            collection: collection,
            rkey: "one"
        )
        let privateOnlyURI = try SpaceRecordURI(
            space: privateSpace,
            author: did,
            collection: collection,
            rkey: "private-only"
        )
        _ = try await database.apply(
            space: privateSpace,
            author: did,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try TID(tidString: "3jzfcijpj2z2b"),
            writes: [
                .put(
                    uri: privateCollisionURI,
                    value: privateCollision,
                    cid: CID.fromDAGCBOR(privateCollision).string
                ),
                .put(
                    uri: privateOnlyURI,
                    value: privateOnly,
                    cid: CID.fromDAGCBOR(privateOnly).string
                ),
            ],
            eventID: UUID()
        )
        let preparationRequestID = "public-read-identity"
        let journal = try PLCAccountPreparationJournal(
            requestID: preparationRequestID,
            canonicalHandle: handle,
            pdsOrigin: "https://swan.example",
            repositoryRevision: "3jzfcijpj2z2a",
            operation: try PLCAccountPreparationOperationFacts(
                signingDIDKey: "did:key:zDnaejgmAHMLkBPMBWnkBxyGxpXx8LgE4WJAYDhwZzyoRAddF",
                rotationDIDKey: "did:key:zDnaeY3trVxVedZS1deaj8NG4QRMu5yrkGMAmcq4VWMckY7fA",
                signature: "9iRdVfzU6ADbVi3zm0V5Qephpl3Dae5odEdDhUBV8aA2TdS1kezQ_9E1YFevVRGE451G_Rdg514dat4ckLGVQg"
            ),
            signingKey: try AccountControlKeyReference(
                purpose: .signing, generation: 1
            ),
            rotationKey: try AccountControlKeyReference(
                purpose: .rotation, generation: 1
            ),
            publicGenesisCommitCID: nil,
            stage: .keysStored
        )
        _ = try await database.installPLCAccountPreparationJournal(journal)
        _ = try await database.advancePLCAccountPreparationJournal(
            requestID: preparationRequestID,
            expectedStage: .keysStored,
            to: .repositoryInstalled,
            publicGenesisCommitCID: genesis.commitCID.string
        )
        _ = try await database.advancePLCAccountPreparationJournal(
            requestID: preparationRequestID,
            expectedStage: .repositoryInstalled,
            to: .submissionPending,
            publicGenesisCommitCID: nil
        )
        _ = try await database.advancePLCAccountPreparationJournal(
            requestID: preparationRequestID,
            expectedStage: .submissionPending,
            to: .submitted,
            publicGenesisCommitCID: nil
        )
        if tamperJournalSignature {
            _ = try await database.connection.query(
                """
                UPDATE plc_account_preparation_journal
                SET operation_signature = ?
                WHERE singleton = 1
                """,
                [.text(String(repeating: "A", count: 86))]
            )
        }
        try await database.close()

        let control = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await control.createAccount(try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: AccountControlKeyReference(
                purpose: .signing, generation: 1
            ),
            rotationKey: AccountControlKeyReference(
                purpose: .rotation, generation: 1
            ),
            publicGenesisCommitCID: genesis.commitCID.string,
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        ))
        var intent = try PLCAccountPreparationIntent(
            requestID: preparationRequestID,
            did: did,
            canonicalHandle: handle,
            pdsOrigin: "https://swan.example",
            repositoryRevision: "3jzfcijpj2z2a",
            operationCID: tamperIntentCID
                ? genesis.emptyMSTCID.string : genesis.commitCID.string,
            stage: .keysStored
        )
        _ = try await control.reservePLCAccountPreparationIntent(intent)
        for next in [
            PLCAccountPreparationStage.repositoryInstalled,
            .submissionPending,
            .submitted,
        ] {
            intent = try await control.advancePLCAccountPreparationIntent(
                requestID: preparationRequestID,
                expectedStage: intent.stage,
                to: next
            )
        }
        let directory: SQLitePreMigratedAccountDirectory
        do {
            directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
                dataDirectory: root,
                controlStore: control,
                publicIdentityVerifier: TestPublicPLCGenesisVerifier(
                    operationCID: genesis.commitCID.string
                ),
                publicCARSpoolAdmission: admission
            )
        } catch {
            // Bootstrap owns and closes account databases on admission
            // failure, but the caller still owns the control connection. Do
            // not let a deliberately invalid identity fixture abort in
            // SQLiteControlDatabase.deinit before XCTest can assert the
            // fail-closed outcome.
            try? await control.close()
            throw error
        }
        return (
            root, control, directory, key, currentState,
            genesis.commitCID.string,
            privateCollision, privateOnly
        )
    }
}

private struct TestPublicPLCGenesisVerifier:
    PublicPLCGenesisVerifying,
    PublicPLCRepositoryAuthenticating
{
    let operationCID: String

    func verifyGenesis(
        facts: PublicPLCGenesisFacts,
        expectedDID: String
    ) throws -> String {
        guard facts.canonicalHandle == "alice.example.com",
              facts.pdsOrigin == "https://swan.example",
              facts.signingDIDKey
                == "did:key:zDnaejgmAHMLkBPMBWnkBxyGxpXx8LgE4WJAYDhwZzyoRAddF",
              facts.rotationDIDKey
                == "did:key:zDnaeY3trVxVedZS1deaj8NG4QRMu5yrkGMAmcq4VWMckY7fA",
              facts.signature
                == "9iRdVfzU6ADbVi3zm0V5Qephpl3Dae5odEdDhUBV8aA2TdS1kezQ_9E1YFevVRGE451G_Rdg514dat4ckLGVQg",
              expectedDID == "did:plc:abcdefghijklmnopqrstuvwx" else {
            throw PublicRepositoryReadError.unavailable
        }
        return operationCID
    }

    func authenticateRepositoryCommit(
        signedCommitBytes: Data,
        expectedCommitCID: CID,
        expectedDID: String,
        signingDIDKey _: String
    ) async throws -> PublicRepositoryCommitAuthentication {
        let commit = try PublicRepositoryCommitCodec.structurallyValidate(
            signedCommitBytes: signedCommitBytes,
            expectedCommitCID: expectedCommitCID
        )
        guard commit.descriptor.did == expectedDID else {
            throw PublicRepositoryReadError.unavailable
        }
        return try PublicRepositoryCommitAuthentication(
            descriptor: commit.descriptor,
            commitCID: commit.commitCID,
            verificationIdentity: "test-structural-verifier"
        )
    }
}

private actor PublicReadCARCollector {
    private(set) var data = Data()
    private(set) var maximumChunk = 0

    func append(_ chunk: Data) {
        data.append(chunk)
        maximumChunk = max(maximumChunk, chunk.count)
    }
}

private actor PublicReadRSSSampler {
    private(set) var peak: Int

    init(initial: Int) {
        peak = initial
    }

    func sample(_ value: Int) {
        peak = max(peak, value)
    }
}

private final class PublicReadHTTPDiscardWriter:
    ResponseBodyWriter,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var bytes = 0
    private var maximum = 0
    private var didFinish = false

    var byteCount: Int { lock.withLock { bytes } }
    var maximumChunkBytes: Int { lock.withLock { maximum } }
    var finished: Bool { lock.withLock { didFinish } }

    func write(_ buffer: ByteBuffer) async throws {
        lock.withLock {
            bytes += buffer.readableBytes
            maximum = max(maximum, buffer.readableBytes)
        }
        await Task.yield()
    }

    func write(contentsOf buffers: some Sequence<ByteBuffer>) async throws {
        for buffer in buffers {
            try await write(buffer)
        }
    }

    consuming func finish(_ trailingHeaders: HTTPFields?) async throws {
        lock.withLock { didFinish = true }
    }
}

private func currentResidentBytes() -> Int {
    #if canImport(Darwin)
    var info = mach_task_basic_info()
    var count = mach_msg_type_number_t(
        MemoryLayout<mach_task_basic_info>.size
            / MemoryLayout<natural_t>.size
    )
    let result = withUnsafeMutablePointer(to: &info) { pointer in
        pointer.withMemoryRebound(
            to: integer_t.self,
            capacity: Int(count)
        ) {
            task_info(
                mach_task_self_,
                task_flavor_t(MACH_TASK_BASIC_INFO),
                $0,
                &count
            )
        }
    }
    return result == KERN_SUCCESS ? Int(info.resident_size) : 0
    #elseif canImport(Glibc)
    guard let fields = try? String(
        contentsOfFile: "/proc/self/statm", encoding: .utf8
    ).split(separator: " "),
          fields.count > 1,
          let pages = Int(fields[1]) else { return 0 }
    return pages * Int(sysconf(Int32(_SC_PAGESIZE)))
    #else
    return 0
    #endif
}

private actor PublicReadCARSource: PublicRepositoryCARByteSource {
    private let data: Data
    private var offset = 0

    init(_ data: Data) {
        self.data = data
    }

    func read(maximumBytes: Int) async throws -> Data? {
        guard offset < data.count else { return nil }
        let end = min(data.count, offset + maximumBytes)
        defer { offset = end }
        return Data(data[offset..<end])
    }
}

private func corruptPublicProjectionIndex(
    connection: SQLiteConnection,
    collection: String,
    recordKey: String,
    replacementCID: String
) async throws {
    _ = try await connection.query(
        """
        UPDATE public_repository_record_index
        SET record_cid = ?
        WHERE collection = ? AND rkey = ?
        """,
        [
            .text(replacementCID),
            .text(collection),
            .text(recordKey),
        ]
    )
    let rows = try await connection.query(
        """
        SELECT record_cid
        FROM public_repository_record_index
        WHERE collection = ? AND rkey = ?
        """,
        [.text(collection), .text(recordKey)]
    )
    guard rows.count == 1,
          rows[0].column("record_cid")?.string == replacementCID else {
        throw PublicRepositoryReadError.unavailable
    }
}

private func withReservedSQLiteWriter(
    databaseURL: URL,
    operation: () async throws -> Void
) async throws {
    let writer = try await SQLiteConnection.open(
        storage: .file(path: databaseURL.path)
    )
    var capturedError: Error?
    do {
        _ = try await writer.query("PRAGMA busy_timeout=0")
        _ = try await writer.query("BEGIN IMMEDIATE")
        try await operation()
    } catch {
        capturedError = error
    }
    _ = try? await writer.query("ROLLBACK")
    try? await writer.close()
    if let capturedError {
        throw capturedError
    }
}

private func XCTAssertThrowsPublicReadUnavailable<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected unavailable", file: file, line: line)
    } catch let error as PublicRepositoryReadError {
        XCTAssertEqual(error, .unavailable, file: file, line: line)
    } catch {
        XCTFail("expected public read unavailable, got \(error)", file: file, line: line)
    }
}

private func XCTAssertThrowsSwanUnavailable<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected unavailable", file: file, line: line)
    } catch let error as SwanError {
        guard case .unavailable = error else {
            return XCTFail(
                "expected unavailable, got \(error)",
                file: file,
                line: line
            )
        }
    } catch {
        XCTFail(
            "expected SwanError.unavailable, got \(error)",
            file: file,
            line: line
        )
    }
}
