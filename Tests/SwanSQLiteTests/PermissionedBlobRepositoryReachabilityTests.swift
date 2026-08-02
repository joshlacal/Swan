import Foundation
import Crypto
import Petrel
import SwanCore
@_spi(PortableRestore) @testable import SwanSQLite
import SwanPublicRepository
import SwanSpaces
import SwanStorage
import XCTest

final class PermissionedBlobRepositoryReachabilityTests: XCTestCase {
    func testPortableRestoreRejectsSpaceBlobWithoutMatchingRepositoryStateAndLeavesNoReference()
        async throws
    {
        let fixture = try PermissionedBlobReachabilityFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        try await fixture.withDatabase { database in
            let payload = Data("orphaned portable space blob".utf8)
            let cid = CID.fromBlob(payload).string
            var rejected = false

            do {
                _ = try await database.restorePortableBlob(
                    payload,
                    expectedCID: cid,
                    namespace: .space(fixture.space)
                )
            } catch {
                rejected = true
            }

            XCTAssertTrue(
                rejected,
                "portable restore must reject a space blob when the account has no matching repository state"
            )
            let inventory = try await database.portableExportInventory()
            XCTAssertFalse(
                inventory.blobs.contains(
                    BlobReference(cid: cid, namespace: .space(fixture.space))
                ),
                "a rejected portable space blob must not leave a namespace reference"
            )
        }
    }

    func testUploadedSpaceBlobWithoutRepositoryStateIsNotReadable() async throws {
        let fixture = try PermissionedBlobReachabilityFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        try await fixture.withDatabase { database in
            let payload = Data("staged orphaned space blob".utf8)
            let reference = try await database.putBlob(
                payload,
                namespace: .space(fixture.space)
            )

            try await assertPermissionedBlobIsUnreadable(
                database,
                fixture: fixture,
                cid: reference.cid
            )
        }
    }

    func testUploadedSpaceBlobWithActiveRepositoryStateRemainsReadable() async throws {
        let fixture = try PermissionedBlobReachabilityFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        try await fixture.withDatabase { database in
            let recordValue = Data([0xa1, 0x61, 0x61, 0x01])
            let recordCID = CID.fromDAGCBOR(recordValue).string
            _ = try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222222"),
                writes: [
                    .create(
                        uri: fixture.record,
                        value: recordValue,
                        cid: recordCID
                    ),
                ]
            )

            let payload = Data("repository-reachable space blob".utf8)
            let reference = try await database.putBlob(
                payload,
                namespace: .space(fixture.space)
            )
            let maybeAuthorized = try await database.permissionedBlob(
                space: fixture.space,
                author: fixture.author,
                cid: reference.cid
            )
            let authorized = try XCTUnwrap(maybeAuthorized)
            var received = Data()
            try await authorized.body.streamBody(maximumChunkBytes: 7) { chunk in
                received.append(chunk)
            }
            XCTAssertEqual(received, payload)
        }
    }

    func testPermissionedRecordPromotesUploadedBlobIntoPrivateNamespace() async throws {
        let fixture = try PermissionedBlobReachabilityFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        try await fixture.withDatabase { database in
            let payload = Data("promoted permissioned blob".utf8)
            let publicReference = try await database.putBlob(
                payload,
                namespace: .public
            )
            let blobCID = try CID.parse(publicReference.cid)
            let value = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
                (key: "$type", value: "app.bsky.feed.post"),
                (key: "text", value: "private blob"),
                (key: "blob", value: OrderedCBORMap(entries: [
                    (key: "$type", value: "blob"),
                    (key: "ref", value: ATProtoLink(cid: blobCID)),
                    (key: "mimeType", value: "application/octet-stream"),
                    (key: "size", value: payload.count),
                ])),
            ]))
            let recordCID = CID.fromDAGCBOR(value).string

            _ = try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222222"),
                writes: [
                    .create(
                        uri: fixture.record,
                        value: value,
                        cid: recordCID
                    ),
                ]
            )

            let remainsPublic = try await database.publicBlobExists(cid: publicReference.cid)
            XCTAssertFalse(
                remainsPublic,
                "a blob attached only to a permissioned record must not remain publicly reachable"
            )
            let privateBlobReference = try await database.permissionedBlob(
                space: fixture.space,
                author: fixture.author,
                cid: publicReference.cid
            )
            let privateBlob = try XCTUnwrap(privateBlobReference)
            var received = Data()
            try await privateBlob.body.streamBody(maximumChunkBytes: 8) { chunk in
                received.append(chunk)
            }
            XCTAssertEqual(received, payload)
        }
    }

    func testPermissionedPromotionRetainsBlobStillReferencedByPublicRecord() async throws {
        let fixture = try PermissionedBlobReachabilityFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        try await fixture.withDatabase { database in
            let payload = Data("shared public and permissioned blob".utf8)
            let publicReference = try await database.putBlob(
                payload,
                namespace: .public
            )
            let blobCID = try CID.parse(publicReference.cid)
            let signingKey = P256.Signing.PrivateKey()
            let genesis = try PublicRepositoryGenesisCodec.create(
                did: fixture.author,
                revision: "3jzfcijpj2z2a",
                signingKey: signingKey
            )
            _ = try await database.installPublicRepositoryGenesis(
                genesis,
                signingPublicKey: signingKey.publicKey,
                installedAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
            let loadedInitial = try await database.loadPublicRepositoryState()
            let initial = try XCTUnwrap(loadedInitial)
            let publicPath = try PublicRepositoryPath(
                collection: "app.bsky.feed.post",
                recordKey: "shared"
            )
            let publicRequest = try PublicRepositoryMutationRequest(
                id: "shared-public-record",
                canonicalDigest: Data(repeating: 0x51, count: 32),
                baseCommitCID: initial.commitCID
            )
            guard case let .reserved(publicReservation) = try await database
                .reservePublicRepositoryRevision(
                    publicRequest,
                    wallClockMicroseconds: 1_750_000_000_000_000
                ) else {
                XCTFail("public request unexpectedly replayed")
                return
            }
            let publicRecord = PublicRecord([
                "$type": .string("app.bsky.feed.post"),
                "text": .string("public reference"),
                "blob": .object([
                    "$type": .string("blob"),
                    "ref": .link(blobCID),
                    "mimeType": .string("application/octet-stream"),
                    "size": .integer(payload.count),
                ]),
            ])
            let prepared = try await PublicRepositoryEngine.apply(
                repositoryDID: fixture.author,
                currentState: initial,
                blocks: database,
                revision: publicReservation.nextRevision,
                batch: try PublicRepositoryWriteBatch(
                    writes: [.create(path: publicPath, record: publicRecord)],
                    expectedCommitCID: initial.commitCID
                ),
                signer: P256PublicRepositoryCommitSigner(privateKey: signingKey)
            )
            _ = try await database.applyPublicRepositoryMutation(
                reservation: publicReservation,
                prepared: prepared
            )

            let permissionedValue = try DAGCBOR.encodeValue(
                OrderedCBORMap(entries: [
                    (key: "$type", value: "app.bsky.feed.post"),
                    (key: "text", value: "private reference"),
                    (key: "blob", value: OrderedCBORMap(entries: [
                        (key: "$type", value: "blob"),
                        (key: "ref", value: ATProtoLink(cid: blobCID)),
                        (key: "mimeType", value: "application/octet-stream"),
                        (key: "size", value: payload.count),
                    ])),
                ])
            )
            _ = try await database.apply(
                space: fixture.space,
                author: fixture.author,
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222222"),
                writes: [
                    .create(
                        uri: fixture.record,
                        value: permissionedValue,
                        cid: CID.fromDAGCBOR(permissionedValue).string
                    ),
                ]
            )

            let remainsPublic = try await database.publicBlobExists(
                cid: publicReference.cid
            )
            let publicData = try await database.publicBlobData(
                cid: publicReference.cid
            )
            let privateBlob = try await database.permissionedBlob(
                space: fixture.space,
                author: fixture.author,
                cid: publicReference.cid
            )
            XCTAssertTrue(
                remainsPublic,
                "a public record reference must preserve public blob reachability"
            )
            XCTAssertEqual(publicData, payload)
            XCTAssertNotNil(privateBlob)
        }
    }
}

private struct PermissionedBlobReachabilityFixture {
    let root: URL
    let author = "did:plc:alice"
    let space: SpaceURI
    let record: SpaceRecordURI

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "PermissionedBlobReachability-\(UUID().uuidString)")
        space = try SpaceURI(
            authority: author,
            spaceType: "app.bsky.bookmarks",
            skey: "self"
        )
        record = try SpaceRecordURI(
            space: space,
            author: author,
            collection: "app.bsky.feed.post",
            rkey: "repository-state"
        )
    }

    func withDatabase<T>(
        _ body: (SQLiteAccountDatabase) async throws -> T
    ) async throws -> T {
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: author
        )
        do {
            let result = try await body(database)
            try await database.close()
            return result
        } catch {
            try? await database.close()
            throw error
        }
    }
}

private func assertPermissionedBlobIsUnreadable(
    _ database: SQLiteAccountDatabase,
    fixture: PermissionedBlobReachabilityFixture,
    cid: String,
    file: StaticString = #filePath,
    line: UInt = #line
) async throws {
    do {
        let blob = try await database.permissionedBlob(
            space: fixture.space,
            author: fixture.author,
            cid: cid
        )
        XCTAssertNil(
            blob,
            "a staged space blob must not be readable before its repository exists",
            file: file,
            line: line
        )
    } catch {
        guard case .unauthorized = error as? SwanError else {
            throw error
        }
    }
}
