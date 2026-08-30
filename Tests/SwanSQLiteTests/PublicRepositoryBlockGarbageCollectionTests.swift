import Crypto
import Foundation
import Petrel
import SQLiteNIO
import PetrelRepo
import SwanStorage
@testable import SwanSQLite
import XCTest

final class PublicRepositoryBlockGarbageCollectionTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let genesisRevision = "3jzfcijpj2z2a"
    private let collection = "app.bsky.feed.post"

    func testSupersededBlocksAreReclaimedWhileCurrentRootBlocksSurviveExport() async throws {
        let fixture = try await makeRepository()
        defer { fixture.cleanUp() }

        let path = try PublicRepositoryPath(collection: collection, recordKey: "item1")

        // Initial create
        _ = try await fixture.commit(
            writes: [
                .create(
                    path: path,
                    record: PublicRecord([
                        "$type": .string(collection),
                        "text": .string("version 1 - initial text"),
                    ])
                ),
            ],
            requestID: "write-1"
        )

        let countAfterCreate = try await fixture.blockCount()

        // Multiple updates creating superseded MST and record blocks
        for updateIndex in 2...10 {
            _ = try await fixture.commit(
                writes: [
                    .update(
                        path: path,
                        record: PublicRecord([
                            "$type": .string(collection),
                            "text": .string("version \(updateIndex) - updated content to generate new blocks"),
                        ]),
                        expectedRecordCID: nil
                    ),
                ],
                requestID: "write-\(updateIndex)"
            )
        }

        let countBeforeGC = try await fixture.blockCount()
        XCTAssertGreaterThan(countBeforeGC, countAfterCreate)

        // Set quota tight enough to force GC on next write
        await fixture.database.setPublicRepositoryBlockQuota(
            PublicRepositoryBlockQuota(
                maximumTotalBytes: 100_000,
                maximumTotalBlocks: countAfterCreate + 2
            )
        )

        // Perform write 11 which will trigger GC
        _ = try await fixture.commit(
            writes: [
                .update(
                    path: path,
                    record: PublicRecord([
                        "$type": .string(collection),
                        "text": .string("version 11 - trigger GC"),
                    ]),
                    expectedRecordCID: nil
                ),
            ],
            requestID: "write-11"
        )

        let countAfterGC = try await fixture.blockCount()
        XCTAssertLessThan(countAfterGC, countBeforeGC, "unreachable superseded blocks must be reclaimed")

        let sink = TestCARByteSink()
        let loadedState = try await fixture.database.loadPublicRepositoryState()
        let state = try XCTUnwrap(loadedState)
        let rawBlock = try await fixture.database.block(for: state.commitCID)
        let commitBlockData = try XCTUnwrap(rawBlock)
        let signedCommit = try await fixture.database.structurallyValidatedCommit(
            signedCommitBytes: commitBlockData,
            expectedCommitCID: state.commitCID
        )
        try await fixture.database.writeBoundedPublicRepositoryCAR(
            state: state,
            commit: signedCommit,
            to: sink
        )
        XCTAssertGreaterThan(sink.bytes.count, 0)
    }

    func testQuotaExceededRejectionRollsBackEntireTransaction() async throws {
        let fixture = try await makeRepository()
        defer { fixture.cleanUp() }

        let path = try PublicRepositoryPath(collection: collection, recordKey: "item1")

        _ = try await fixture.commit(
            writes: [
                .create(
                    path: path,
                    record: PublicRecord([
                        "$type": .string(collection),
                        "text": .string("initial"),
                    ])
                ),
            ],
            requestID: "initial-write"
        )
        let loadedStateBefore = try await fixture.database.loadPublicRepositoryState()
        let stateBefore = try XCTUnwrap(loadedStateBefore)
        let blocksBefore = try await fixture.blockCount()

        // Set impossibly small quota
        await fixture.database.setPublicRepositoryBlockQuota(
            PublicRepositoryBlockQuota(
                maximumTotalBytes: 10,
                maximumTotalBlocks: 1
            )
        )

        var thrownError: Error?
        do {
            _ = try await fixture.commit(
                writes: [
                    .create(
                        path: try PublicRepositoryPath(collection: collection, recordKey: "item2"),
                        record: PublicRecord([
                            "$type": .string(collection),
                            "text": .string("overflow"),
                        ])
                    ),
                ],
                requestID: "overflow-write"
            )
        } catch {
            thrownError = error
        }

        guard let storeError = thrownError as? PublicRepositoryMutationStoreError,
              storeError == .blockQuotaExceeded else {
            return XCTFail("expected blockQuotaExceeded, got \(String(describing: thrownError))")
        }

        let loadedStateAfter = try await fixture.database.loadPublicRepositoryState()
        let stateAfter = try XCTUnwrap(loadedStateAfter)
        XCTAssertEqual(stateAfter, stateBefore)

        // Verify record index is unchanged
        let indexed = try await fixture.database.publicRepositoryRecordCID(
            for: try PublicRepositoryPath(collection: collection, recordKey: "item2")
        )
        XCTAssertNil(indexed)

        // Verify blocks rolled back
        let blocksAfter = try await fixture.blockCount()
        XCTAssertEqual(blocksAfter, blocksBefore)
    }

    func testOverQuotaRepositoryAdmitsDeleteOnlyMutationThatShrinksRepository() async throws {
        let fixture = try await makeRepository()
        defer { fixture.cleanUp() }

        let path1 = try PublicRepositoryPath(collection: collection, recordKey: "item1")
        let path2 = try PublicRepositoryPath(collection: collection, recordKey: "item2")

        _ = try await fixture.commit(
            writes: [
                .create(
                    path: path1,
                    record: PublicRecord([
                        "$type": .string(collection),
                        "text": .string("initial item 1"),
                    ])
                ),
                .create(
                    path: path2,
                    record: PublicRecord([
                        "$type": .string(collection),
                        "text": .string("initial item 2"),
                    ])
                ),
            ],
            requestID: "create-items"
        )
        // Run GC once to clean up any superseded blocks so only reachable blocks remain
        let loadedStateAfterCreate = try await fixture.database.loadPublicRepositoryState()
        let stateAfterCreate = try XCTUnwrap(loadedStateAfterCreate)
        try await fixture.database.garbageCollectPublicRepositoryBlocksWithoutGate(state: stateAfterCreate)
        let reachableBlockCount = try await fixture.blockCount()

        // Set quota below reachable count to simulate over-quota state
        await fixture.database.setPublicRepositoryBlockQuota(
            PublicRepositoryBlockQuota(
                maximumTotalBytes: 1_000_000,
                maximumTotalBlocks: 3
            )
        )

        // A create/growth write must be rejected
        do {
            _ = try await fixture.commit(
                writes: [
                    .create(
                        path: try PublicRepositoryPath(collection: collection, recordKey: "item3"),
                        record: PublicRecord([
                            "$type": .string(collection),
                            "text": .string("overflow item 3"),
                        ])
                    ),
                ],
                requestID: "overflow-growth"
            )
            XCTFail("growth write when over quota must fail")
        } catch let storeError as PublicRepositoryMutationStoreError {
            XCTAssertEqual(storeError, .blockQuotaExceeded)
        }

        // A delete-only mutation that shrinks the repository must be admitted
        _ = try await fixture.commit(
            writes: [
                .delete(path: path1, expectedRecordCID: nil),
            ],
            requestID: "shrink-delete"
        )

        // Verify item1 is deleted
        let indexed = try await fixture.database.publicRepositoryRecordCID(for: path1)
        XCTAssertNil(indexed, "deleted item must be removed from record index")
    }

    // MARK: - Helpers

    private struct Repository {
        let root: URL
        let database: SQLiteAccountDatabase
        let key: P256.Signing.PrivateKey

        func cleanUp() {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }

        func blockCount() async throws -> Int {
            let connection = try await SQLiteConnection.open(
                storage: .file(path: SQLiteLayout.accountDatabase(in: root, did: "did:plc:abcdefghijklmnopqrstuvwx").path)
            )
            defer { Task { try? await connection.close() } }
            let rows = try await connection.query("SELECT COUNT(*) AS c FROM public_repository_blocks")
            return rows.first?.column("c")?.integer ?? 0
        }

        func commit(
            writes: [PublicRepositoryWrite],
            requestID: String
        ) async throws -> CommittedPublicRepositoryMutation {
            let loaded = try await database.loadPublicRepositoryState()
            let current = try XCTUnwrap(loaded)
            let request = try PublicRepositoryMutationRequest(
                id: requestID,
                canonicalDigest: Data(SHA256.hash(data: Data(requestID.utf8))),
                baseCommitCID: current.commitCID
            )
            let reservation: PublicRepositoryMutationReservation
            switch try await database.reservePublicRepositoryRevision(
                request,
                wallClockMicroseconds: UInt64(Date().timeIntervalSince1970 * 1_000_000)
            ) {
            case let .reserved(value):
                reservation = value
            case .committed:
                throw PublicRepositoryMutationStoreError.conflictingRequestReuse
            }
            let prepared = try await PublicRepositoryEngine.apply(
                repositoryDID: database.publicRepositoryDID(),
                currentState: current,
                blocks: database,
                revision: reservation.nextRevision,
                batch: try PublicRepositoryWriteBatch(
                    writes: writes,
                    expectedCommitCID: current.commitCID
                ),
                signer: P256PublicRepositoryCommitSigner(privateKey: key)
            )
            do {
                return try await database.applyPublicRepositoryMutation(
                    reservation: reservation,
                    prepared: prepared
                )
            } catch {
                try? await database.abandonPublicRepositoryReservation(reservation)
                throw error
            }
        }
    }

    private func makeRepository() async throws -> Repository {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "PublicRepositoryBlockGCTests-" + UUID().uuidString
        )
        let key = P256.Signing.PrivateKey()
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let genesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: genesisRevision,
            signingKey: key
        )
        _ = try await database.installPublicRepositoryGenesis(
            genesis,
            signingPublicKey: key.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
        return Repository(root: root, database: database, key: key)
    }
}

private final class TestCARByteSink: PublicRepositoryCARByteSink, @unchecked Sendable {
    var bytes = Data()

    func write(_ chunk: Data) async throws {
        bytes.append(chunk)
    }

    func close() async throws {}
}
