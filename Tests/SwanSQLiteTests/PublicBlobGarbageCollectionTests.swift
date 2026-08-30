import Crypto
import Foundation
import Petrel
import SQLiteNIO
import PetrelRepo
import SwanStorage
@testable import SwanSQLite
import XCTest

final class PublicBlobGarbageCollectionTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let genesisRevision = "3jzfcijpj2z2a"
    private let collection = "app.bsky.feed.post"

    func testPublicBlobPurgePreservesBlobReferencedByConcurrentCommitDuringSweep() async throws {
        let fixture = try await makeRepository()
        defer { fixture.cleanUp() }

        let blobBytes = Data("racing blob content".utf8)
        let uploaded = try await fixture.database.putBlob(blobBytes, namespace: .public)
        let blobCID = uploaded.cid

        // Age the blob reference so it's older than cutoff
        try await withRawConnection(root: fixture.root) { conn in
            _ = try await conn.query(
                "UPDATE blob_namespace_references SET created_at = 100 WHERE cid = ? AND namespace_kind = 'public'",
                [.text(blobCID)]
            )
        }

        // Install hook that commits a record referencing the blob after candidates are selected
        let targetCollection = self.collection
        await fixture.database.installTestingHooks(SQLiteTestingHooks(
            afterPublicBlobPurgeCandidateSelection: {
                let parsedCID = try CID.parse(blobCID)
                let record = PublicRecord([
                    "$type": .string(targetCollection),
                    "blob": .object([
                        "$type": .string("blob"),
                        "ref": .link(parsedCID),
                        "mimeType": .string("application/octet-stream"),
                        "size": .integer(blobBytes.count),
                    ]),
                ])
                _ = try await fixture.commit(
                    writes: [
                        .create(
                            path: try PublicRepositoryPath(collection: targetCollection, recordKey: "race-item"),
                            record: record
                        ),
                    ],
                    requestID: "concurrent-commit"
                )
            }
        ))

        // Run purge with cutoff > 100
        let purged = try await fixture.database.purgeUnreferencedPublicBlobReferences(
            now: Date(timeIntervalSince1970: 500)
        )
        XCTAssertEqual(purged, 0, "concurrently referenced blob must not be purged")

        // Verify blob reference and payload still exist
        let reachable = try await fixture.database.publicRepositoryContainsBlobCIDWithoutGate(blobCID)
        XCTAssertTrue(reachable, "blob must be reachable in public repository")

        try await withRawConnection(root: fixture.root) { conn in
            let rows = try await conn.query(
                "SELECT 1 FROM blob_namespace_references WHERE cid = ? AND namespace_kind = 'public'",
                [.text(blobCID)]
            )
            XCTAssertFalse(rows.isEmpty, "public blob reference must be preserved")
        }
    }

    func testPublicBlobPurgeReclaimsTrulyUnreferencedBlob() async throws {
        let fixture = try await makeRepository()
        defer { fixture.cleanUp() }

        let blobBytes = Data("unreferenced blob content".utf8)
        let uploaded = try await fixture.database.putBlob(blobBytes, namespace: .public)
        let blobCID = uploaded.cid

        // Age the blob reference
        try await withRawConnection(root: fixture.root) { conn in
            _ = try await conn.query(
                "UPDATE blob_namespace_references SET created_at = 100 WHERE cid = ? AND namespace_kind = 'public'",
                [.text(blobCID)]
            )
        }

        let purged = try await fixture.database.purgeUnreferencedPublicBlobReferences(
            now: Date(timeIntervalSince1970: 500)
        )
        XCTAssertEqual(purged, 1, "truly unreferenced blob must be purged")

        try await withRawConnection(root: fixture.root) { conn in
            let rows = try await conn.query(
                "SELECT 1 FROM blob_namespace_references WHERE cid = ? AND namespace_kind = 'public'",
                [.text(blobCID)]
            )
            XCTAssertTrue(rows.isEmpty, "public blob reference must be deleted")
        }
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
            path: "PublicBlobGarbageCollectionTests-" + UUID().uuidString
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
}
