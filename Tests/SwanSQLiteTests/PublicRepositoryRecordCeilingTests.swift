import Crypto
import Foundation
import Petrel
import SQLiteNIO
import PetrelRepo
import SwanStorage
@testable import SwanSQLite
import XCTest

/// The public read surface refuses an account whose record index exceeds
/// `PublicRepositoryReadLimits.maximumGenerationIndexEntries`, and nothing on
/// the mutation path used to count. An account could therefore write itself
/// past that bound with ordinary `createRecord` traffic and permanently lose
/// `getRecord`, `listRecords`, `getLatestCommit` and `getRepo` while writes
/// kept succeeding — self-inflicted, with no attacker and no way to read its
/// way back out.
///
/// These tests pad `public_repository_record_index` directly rather than
/// committing a hundred thousand real records. That is legitimate here: the
/// bound under test is a property of the index's cardinality, the read-side
/// preflight reads only that table, and the mutation path's own consistency
/// checks (`validatedProjection`) are per-path lookups that padding rows
/// elsewhere in the table cannot affect.
final class PublicRepositoryRecordCeilingTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let genesisRevision = "3jzfcijpj2z2a"
    private let collection = "app.bsky.feed.post"

    private var ceiling: Int { PublicRepositoryReadLimits.maximumGenerationIndexEntries }

    /// The read breakage itself. This is the behaviour the write-side ceiling
    /// exists to keep unreachable; it is expected to hold both before and
    /// after that ceiling lands.
    func testRecordIndexOverTheCeilingRefusesEveryPublicRead() async throws {
        let fixture = try await makeRepository()
        defer { fixture.cleanUp() }

        try await fixture.verifyProjection()

        try await padRecordIndex(root: fixture.root, rows: ceiling + 1)

        var thrown: Error?
        do {
            try await fixture.database.verifyPublicRepositoryProjection()
        } catch {
            thrown = error
        }
        XCTAssertEqual(
            thrown as? PublicRepositoryReadError,
            .resourceLimitExceeded,
            "an index above the ceiling must refuse the read-path projection admission"
        )
    }

    /// The defect: at the ceiling, one more `createRecord` is accepted, and the
    /// account's public reads are dead from that commit onward.
    func testCreateThatWouldCrossTheReadCeilingIsRefused() async throws {
        let fixture = try await makeRepository()
        defer { fixture.cleanUp() }

        try await padRecordIndex(root: fixture.root, rows: ceiling)

        var thrown: Error?
        do {
            _ = try await fixture.commit(
                writes: [
                    .create(
                        path: try PublicRepositoryPath(
                            collection: collection, recordKey: "over-the-ceiling"
                        ),
                        record: PublicRecord([
                            "$type": .string(collection),
                            "text": .string("must not commit"),
                        ])
                    ),
                ],
                requestID: "over-the-ceiling"
            )
        } catch {
            thrown = error
        }
        XCTAssertEqual(
            thrown as? PublicRepositoryReadError,
            .resourceLimitExceeded,
            "a create that would push the record index past the read ceiling must be refused"
        )

        let indexed = try await recordIndexCount(root: fixture.root)
        XCTAssertEqual(indexed, ceiling, "the refused create must leave no durable index row")
    }

    /// A repository that is already over the ceiling — by import, by an older
    /// build, or by operator repair — must still be able to shrink. A check
    /// that refuses deletes on a full repository is a trap with no exit.
    func testOverCeilingRepositoryCanStillDeleteAndUpdate() async throws {
        let fixture = try await makeRepository()
        defer { fixture.cleanUp() }

        let path = try PublicRepositoryPath(
            collection: collection, recordKey: "shrinkable"
        )
        _ = try await fixture.commit(
            writes: [
                .create(
                    path: path,
                    record: PublicRecord([
                        "$type": .string(collection),
                        "text": .string("before"),
                    ])
                ),
            ],
            requestID: "shrinkable-create"
        )

        // Push the index well past the ceiling behind the mutation path's back.
        try await padRecordIndex(root: fixture.root, rows: ceiling + 64)

        // An update keeps cardinality flat and must be admitted.
        _ = try await fixture.commit(
            writes: [
                .update(
                    path: path,
                    record: PublicRecord([
                        "$type": .string(collection),
                        "text": .string("after"),
                    ]),
                    expectedRecordCID: nil
                ),
            ],
            requestID: "shrinkable-update"
        )

        // A delete shrinks it and must be admitted.
        _ = try await fixture.commit(
            writes: [.delete(path: path, expectedRecordCID: nil)],
            requestID: "shrinkable-delete"
        )

        // `padRecordIndex` tops the index up to a total, so the padded state
        // already counted the one real record; deleting it leaves one fewer.
        let indexed = try await recordIndexCount(root: fixture.root)
        XCTAssertEqual(indexed, ceiling + 63)
    }

    /// One number, enforced in two modules. If these ever drift, a repository
    /// can be written into a state its own read path refuses.
    func testWriteCeilingMatchesTheImportLeafCeiling() {
        XCTAssertEqual(
            PublicRepositoryLimits.standard.maximumRepositoryRecords,
            PublicRepositoryReadLimits.maximumGenerationIndexEntries
        )
    }

    // MARK: - Fixture

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

        func verifyProjection() async throws {
            try await database.verifyPublicRepositoryProjection()
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
            path: "PublicRepositoryRecordCeilingTests-" + UUID().uuidString
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

    /// Fills the record index to exactly `rows` entries using one recursive
    /// `INSERT ... SELECT`. Round-tripping a hundred thousand statements
    /// through the connection actor would dominate the test's runtime and
    /// measure nothing the bound cares about.
    private func padRecordIndex(root: URL, rows: Int) async throws {
        let total = try await withRawConnection(root: root) { connection in
            let existing = try await self.count(on: connection)
            let missing = rows - existing
            guard missing > 0 else { return existing }
            _ = try await connection.query(
                """
                INSERT INTO public_repository_record_index(collection, rkey, record_cid)
                WITH RECURSIVE filler(n) AS (
                    SELECT 1 UNION ALL SELECT n + 1 FROM filler WHERE n < ?
                )
                SELECT ?, 'padding' || printf('%013d', n), ?
                FROM filler
                """,
                [
                    .integer(missing),
                    .text(self.collection),
                    .text("bafyreicl5wcgzaefpu23bimapxa4lj7kbx7dczrtbmh6haqztpqkjk6uza"),
                ]
            )
            return try await self.count(on: connection)
        }
        XCTAssertEqual(total, rows)
    }

    private func recordIndexCount(root: URL) async throws -> Int {
        try await withRawConnection(root: root) { try await self.count(on: $0) }
    }

    /// Closed deterministically rather than in a detached task: the account
    /// database holds its own connection to the same WAL file and the next
    /// mutation must not race a still-open reader.
    private func withRawConnection<T>(
        root: URL,
        _ body: (SQLiteConnection) async throws -> T
    ) async throws -> T {
        let connection = try await SQLiteConnection.open(storage: .file(
            path: SQLiteLayout.accountDatabase(in: root, did: did).path
        ))
        _ = try? await connection.query("PRAGMA busy_timeout=5000")
        do {
            let value = try await body(connection)
            try await connection.close()
            return value
        } catch {
            try? await connection.close()
            throw error
        }
    }

    private func count(on connection: SQLiteConnection) async throws -> Int {
        let rows = try await connection.query(
            "SELECT COUNT(*) AS row_count FROM public_repository_record_index"
        )
        guard case let .integer(value) = rows.first?.column("row_count") else {
            throw PublicRepositoryMutationStoreError.corruptRepository
        }
        return value
    }
}
