import Crypto
import Foundation
import Hummingbird
import HTTPTypes
import Petrel
import SwanPublicRepository
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import SwanHTTP
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
        let fixture = try await makeFixture(tamperPublicIndex: true)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        await XCTAssertThrowsPublicReadUnavailable(
            try await fixture.directory.publicRepositoryCAR(selector: did)
        )
        try await fixture.directory.close()
        try await fixture.control.close()
    }

    func testDescribeRepoFailsClosedForTamperedGenesisAndIntentCID() async throws {
        let signatureFixture = try await makeFixture(
            tamperJournalSignature: true
        )
        defer { try? FileManager.default.removeItem(at: signatureFixture.root) }
        await XCTAssertThrowsPublicReadUnavailable(
            try await signatureFixture.directory.describePublicRepository(
                selector: did
            )
        )
        try await signatureFixture.directory.close()
        try await signatureFixture.control.close()

        let intentFixture = try await makeFixture(tamperIntentCID: true)
        defer { try? FileManager.default.removeItem(at: intentFixture.root) }
        await XCTAssertThrowsPublicReadUnavailable(
            try await intentFixture.directory.describePublicRepository(
                selector: did
            )
        )
        try await intentFixture.directory.close()
        try await intentFixture.control.close()
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

    private func makeFixture(
        admission: PublicRepositorySpoolAdmission? = nil,
        tamperPublicIndex: Bool = false,
        tamperJournalSignature: Bool = false,
        tamperIntentCID: Bool = false
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
        let request = try PublicRepositoryMutationRequest(
            id: "public-read-fixture",
            canonicalDigest: Data(repeating: 0x43, count: 32),
            baseCommitCID: initial.commitCID
        )
        guard case let .reserved(reservation) =
            try await database.reservePublicRepositoryRevision(
                request,
                wallClockMicroseconds: 1_750_000_001_000_000
            ) else {
            throw PublicRepositoryReadError.unavailable
        }
        let writes: [PublicRepositoryWrite] = try ["one", "two", "three"].map {
            let path = try PublicRepositoryPath(
                collection: collection, recordKey: $0
            )
            return .create(
                path: path,
                record: [
                    "$type": .string(collection),
                    "text": .string("public-\($0)"),
                ]
            )
        }
        let prepared = try await PublicRepositoryEngine.apply(
            repositoryDID: did,
            currentState: initial,
            blocks: database,
            revision: reservation.nextRevision,
            batch: try PublicRepositoryWriteBatch(
                writes: writes,
                expectedCommitCID: initial.commitCID
            ),
            signer: P256PublicRepositoryCommitSigner(privateKey: key)
        )
        _ = try await database.applyPublicRepositoryMutation(
            reservation: reservation, prepared: prepared
        )
        let privateCollision = Data("permissioned-private-one".utf8)
        let privateOnly = Data("permissioned-private-only".utf8)
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
                    cid: "cid:permissioned-collision"
                ),
                .put(
                    uri: privateOnlyURI,
                    value: privateOnly,
                    cid: "cid:permissioned-only"
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
        if tamperPublicIndex {
            _ = try await database.connection.query(
                """
                UPDATE public_repository_record_index
                SET record_cid = ?
                WHERE collection = ? AND rkey = ?
                """,
                [
                    .text(genesis.emptyMSTCID.string),
                    .text(collection), .text("one"),
                ]
            )
        }
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
        let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: root,
            controlStore: control,
            publicIdentityVerifier: TestPublicPLCGenesisVerifier(
                operationCID: genesis.commitCID.string
            ),
            publicCARSpoolAdmission: admission
        )
        return (
            root, control, directory, key, prepared.state,
            genesis.commitCID.string,
            privateCollision, privateOnly
        )
    }
}

private struct TestPublicPLCGenesisVerifier: PublicPLCGenesisVerifying {
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
