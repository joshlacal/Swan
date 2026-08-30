import Foundation
import Crypto
import Petrel
import SQLiteNIO
import PetrelRepo
import SwanStorage
@testable import SwanSQLite
import XCTest

final class PublicBlobGarbageCollectionTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let genesisRevision = "3jzfcijpj2z2a"

    func testPublicBlobPurgeRacesWithPublicRecordCommitAndRetainsLiveBlob() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "PublicBlobGCTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        defer { try? FileManager.default.removeItem(at: root) }
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

        // 1. Put two public blobs: blob A (will be claimed during sweep race) and blob B (remains orphaned)
        let payloadA = Data("live-racing-blob-payload".utf8)
        let refA = try await database.putBlob(payloadA, namespace: .public, mimeType: "text/plain")
        let blobCIDA = try CID.parse(refA.cid)
        let payloadB = Data("orphaned-blob-payload".utf8)
        let refB = try await database.putBlob(payloadB, namespace: .public, mimeType: "text/plain")

        // 2. Backdate created_at for both references so they are eligible for purging (older than 14-day grace period)
        let oldTimestamp = Int(Date().timeIntervalSince1970) - (15 * 24 * 60 * 60)
        let raw = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(in: root, did: did).path)
        )
        _ = try await raw.query(
            "UPDATE blob_namespace_references SET created_at = ? WHERE namespace_kind = 'public'",
            [.integer(oldTimestamp)]
        )
        try await raw.close()

        // 3. Prepare a commit that references blob A
        let maybeState = try await database.loadPublicRepositoryState()
        let state = try XCTUnwrap(maybeState)
        let request = try PublicRepositoryMutationRequest(
            id: "race-commit",
            canonicalDigest: Data(repeating: 0x88, count: 32),
            baseCommitCID: state.commitCID
        )
        guard case let .reserved(reservation) = try await database.reservePublicRepositoryRevision(
            request,
            wallClockMicroseconds: 1_750_000_000_000_000
        ) else {
            return XCTFail("failed to reserve revision")
        }
        let path = try PublicRepositoryPath(collection: "app.bsky.feed.post", recordKey: "raced-post")
        let prepared = try await PublicRepositoryEngine.apply(
            repositoryDID: did,
            currentState: state,
            blocks: database,
            revision: reservation.nextRevision,
            batch: try PublicRepositoryWriteBatch(
                writes: [.create(
                    path: path,
                    record: PublicRecord([
                        "$type": .string("app.bsky.feed.post"),
                        "blob": .link(blobCIDA),
                    ])
                )],
                expectedCommitCID: state.commitCID
            ),
            signer: P256PublicRepositoryCommitSigner(privateKey: key)
        )

        // 4. Install hook to commit the record AFTER candidate sweep selection but BEFORE deletion
        await database.installTestingHooks(SQLiteTestingHooks(
            afterPublicBlobPurgeCandidateSelection: {
                _ = try await database.applyPublicRepositoryMutation(
                    reservation: reservation,
                    prepared: prepared
                )
            }
        ))

        // 5. Run purge
        _ = try await database.purgeUnreferencedPublicBlobReferences()

        // 6. Assert blob A's public edge and payload survived
        let rawVerify = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(in: root, did: did).path)
        )
        let edgeA = try await rawVerify.query(
            "SELECT 1 FROM blob_namespace_references WHERE cid = ? AND namespace_kind = 'public'",
            [.text(refA.cid)]
        )
        XCTAssertFalse(edgeA.isEmpty, "Public blob A edge must survive when claimed during sweep race")

        let payloadRowA = try await rawVerify.query(
            "SELECT 1 FROM blob_payloads WHERE cid = ?",
            [.text(refA.cid)]
        )
        XCTAssertFalse(payloadRowA.isEmpty, "Public blob A payload must survive when claimed during sweep race")

        // 7. Assert truly unreachable blob B was reclaimed
        let edgeB = try await rawVerify.query(
            "SELECT 1 FROM blob_namespace_references WHERE cid = ? AND namespace_kind = 'public'",
            [.text(refB.cid)]
        )
        XCTAssertTrue(edgeB.isEmpty, "Orphaned public blob B edge must be deleted")

        let payloadRowB = try await rawVerify.query(
            "SELECT 1 FROM blob_payloads WHERE cid = ?",
            [.text(refB.cid)]
        )
        XCTAssertTrue(payloadRowB.isEmpty, "Orphaned public blob B payload must be deleted")

        try await rawVerify.close()
        try await database.close()
    }
}
