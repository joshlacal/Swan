import Foundation
import Crypto
import Petrel
import SQLiteNIO
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
            let inventory = try await database.portableExportInventory()
            XCTAssertFalse(
                inventory.blobs.contains(reference),
                "staged private blobs without repository truth are not portable"
            )
        }
    }

    func testStagedPrivateBlobDoesNotHideSamePayloadPublicReferenceFromExport()
        async throws
    {
        let fixture = try PermissionedBlobReachabilityFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        try await fixture.withDatabase { database in
            let payload = Data("shared staged and public payload".utf8)
            let publicReference = try await database.putBlob(
                payload, namespace: .public
            )
            let stagedReference = try await database.putBlob(
                payload, namespace: .space(fixture.space)
            )
            XCTAssertEqual(publicReference.cid, stagedReference.cid)

            let inventory = try await database.portableExportInventory()
            XCTAssertTrue(inventory.blobs.contains(publicReference))
            XCTAssertFalse(inventory.blobs.contains(stagedReference))
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
                namespace: .public,
                mimeType: "application/octet-stream"
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
                namespace: .public,
                mimeType: "application/octet-stream"
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

    func testRetainedPublicPromotionAdmitsBothMissingEdgesAtReferenceLimit() async throws {
        let fixture = try PermissionedBlobReachabilityFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let quota = AccountBlobQuota(maximumUniqueBytes: 1_024, maximumReferences: 4)

        try await fixture.withDatabase(blobQuota: quota) { database in
            let payload = Data("quota-shared-public-blob".utf8)
            let uploaded = try await database.putBlob(
                payload,
                namespace: .public,
                mimeType: "application/octet-stream"
            )
            let blobCID = try CID.parse(uploaded.cid)
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
                collection: "app.bsky.feed.post", recordKey: "quota-shared"
            )
            let request = try PublicRepositoryMutationRequest(
                id: "quota-shared-public-record",
                canonicalDigest: Data(repeating: 0x61, count: 32),
                baseCommitCID: initial.commitCID
            )
            guard case let .reserved(reservation) = try await database
                .reservePublicRepositoryRevision(
                    request,
                    wallClockMicroseconds: 1_750_000_000_000_000
                ) else {
                return XCTFail("public request unexpectedly replayed")
            }
            let publicRecord = PublicRecord([
                "$type": .string("app.bsky.feed.post"),
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
                revision: reservation.nextRevision,
                batch: try PublicRepositoryWriteBatch(
                    writes: [.create(path: publicPath, record: publicRecord)],
                    expectedCommitCID: initial.commitCID
                ),
                signer: P256PublicRepositoryCommitSigner(privateKey: signingKey)
            )
            _ = try await database.applyPublicRepositoryMutation(
                reservation: reservation, prepared: prepared
            )

            let privateValue = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
                (key: "$type", value: "app.bsky.feed.post"),
                (key: "blob", value: OrderedCBORMap(entries: [
                    (key: "$type", value: "blob"),
                    (key: "ref", value: ATProtoLink(cid: blobCID)),
                    (key: "mimeType", value: "application/octet-stream"),
                    (key: "size", value: payload.count),
                ])),
            ]))
            let privateCID = CID.fromDAGCBOR(privateValue).string
            _ = try await database.apply(
                space: fixture.space, author: fixture.author,
                expectedRevision: 0, requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222222"),
                writes: [.create(
                    uri: fixture.record, value: privateValue, cid: privateCID
                )]
            )
            try await database.removeBlobReference(uploaded)
            await database.installTestingHooks(SQLiteTestingHooks(
                permissionedBlobPublicReachabilityOverride: { cid in
                    cid == uploaded.cid ? true : nil
                }
            ))
            let fillerOne = try await database.putBlob(Data("filler-one".utf8), namespace: .public)
            let fillerTwo = try await database.putBlob(Data("filler-two".utf8), namespace: .public)

            let secondSpace = try SpaceURI(
                authority: fixture.author,
                spaceType: "app.bsky.bookmarks",
                skey: "quota-second"
            )
            let secondRecord = try SpaceRecordURI(
                space: secondSpace,
                author: fixture.author,
                collection: "app.bsky.feed.post",
                rkey: "repository-state"
            )
            do {
                _ = try await database.apply(
                    space: secondSpace, author: fixture.author,
                    expectedRevision: 0, requestID: UUID(),
                    wireRevision: try TID(tidString: "2222222222223"),
                    writes: [.create(
                        uri: secondRecord, value: privateValue, cid: privateCID
                    )]
                )
                XCTFail("promotion must reject both planned edges at the limit")
            } catch {
                XCTAssertEqual(
                    error as? BlobQuotaError,
                    .referenceCountExceeded(limit: 4)
                )
            }
            let publicAfterRejectedPromotion = try await database.publicBlobExists(
                cid: uploaded.cid
            )
            XCTAssertFalse(publicAfterRejectedPromotion)
            let rejectedRepositoryState = try await database.repositoryState(
                space: secondSpace,
                author: fixture.author
            )
            XCTAssertNil(
                rejectedRepositoryState,
                "quota rejection must not create the second repository"
            )
            let rejectedRecord = try await database.spaceRecord(secondRecord)
            XCTAssertNil(
                rejectedRecord,
                "quota rejection must not persist the rejected record"
            )
            let rejectedInventory = try await blobReferenceInventory(
                fixture: fixture,
                cid: uploaded.cid
            )
            XCTAssertEqual(rejectedInventory.totalReferenceCount, 3)
            XCTAssertFalse(
                rejectedInventory.references.contains(
                    .init(namespaceKind: "space", spaceURI: secondSpace.rawValue)
                ),
                "quota rejection must not persist a second-space private edge"
            )
            XCTAssertFalse(
                rejectedInventory.references.contains(
                    .init(namespaceKind: "public", spaceURI: "")
                ),
                "quota rejection must not persist the planned public edge"
            )

            try await database.removeBlobReference(fillerTwo)
            XCTAssertNotEqual(fillerOne.cid, fillerTwo.cid)
            _ = try await database.apply(
                space: secondSpace, author: fixture.author,
                expectedRevision: 0, requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222223"),
                writes: [.create(
                    uri: secondRecord, value: privateValue, cid: privateCID
                )]
            )
            let publicAfterAdmittedPromotion = try await database.publicBlobExists(
                cid: uploaded.cid
            )
            XCTAssertTrue(publicAfterAdmittedPromotion)
        }
    }

    func testRepeatedPrivatePromotionRemovesRecreatedPublicStagingReference() async throws {
        let fixture = try PermissionedBlobReachabilityFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        try await fixture.withDatabase { database in
            let payload = Data("recreated staged public reference".utf8)
            let firstUpload = try await database.putBlob(
                payload, namespace: .public, mimeType: "application/octet-stream"
            )
            let blobCID = try CID.parse(firstUpload.cid)
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
                space: fixture.space, author: fixture.author,
                expectedRevision: 0, requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222222"),
                writes: [.create(uri: fixture.record, value: value, cid: recordCID)]
            )
            let publicAfterFirstPromotion = try await database.publicBlobExists(
                cid: firstUpload.cid
            )
            XCTAssertFalse(publicAfterFirstPromotion)

            let secondUpload = try await database.putBlob(
                payload, namespace: .public, mimeType: "application/octet-stream"
            )
            XCTAssertEqual(secondUpload.cid, firstUpload.cid)
            let publicAfterReupload = try await database.publicBlobExists(
                cid: firstUpload.cid
            )
            XCTAssertTrue(publicAfterReupload)

            _ = try await database.apply(
                space: fixture.space, author: fixture.author,
                expectedRevision: 1, requestID: UUID(),
                wireRevision: try TID(tidString: "2222222222223"),
                writes: [.update(uri: fixture.record, value: value, cid: recordCID)]
            )
            let publicAfterSecondPromotion = try await database.publicBlobExists(
                cid: firstUpload.cid
            )
            XCTAssertFalse(
                publicAfterSecondPromotion,
                "private idempotency must not bypass staged public-reference cleanup"
            )
            let privateBlob = try await database.permissionedBlob(
                space: fixture.space, author: fixture.author, cid: firstUpload.cid
            )
            XCTAssertNotNil(privateBlob)
        }
    }
}

private struct BlobReferenceInventoryEntry: Hashable {
    let namespaceKind: String
    let spaceURI: String
}

private struct BlobReferenceInventory {
    let totalReferenceCount: Int
    let references: Set<BlobReferenceInventoryEntry>
}

private func blobReferenceInventory(
    fixture: PermissionedBlobReachabilityFixture,
    cid: String
) async throws -> BlobReferenceInventory {
    let connection = try await SQLiteConnection.open(
        storage: .file(path: SQLiteLayout.accountDatabase(
            in: fixture.root,
            did: fixture.author
        ).path)
    )
    do {
        let countRows = try await connection.query(
            "SELECT COUNT(*) AS reference_count FROM blob_namespace_references"
        )
        let referenceRows = try await connection.query(
            """
            SELECT namespace_kind, space_uri
            FROM blob_namespace_references
            WHERE cid = ?
            ORDER BY namespace_kind, space_uri
            """,
            [.text(cid)]
        )
        guard countRows.count == 1,
              let totalReferenceCount = countRows[0]
                .column("reference_count")?.integer else {
            throw BlobReferenceInventoryError.invalidRows
        }
        let references = try Set(referenceRows.map { row in
            guard let namespaceKind = row.column("namespace_kind")?.string,
                  let spaceURI = row.column("space_uri")?.string else {
                throw BlobReferenceInventoryError.invalidRows
            }
            return BlobReferenceInventoryEntry(
                namespaceKind: namespaceKind,
                spaceURI: spaceURI
            )
        })
        try await connection.close()
        return BlobReferenceInventory(
            totalReferenceCount: totalReferenceCount,
            references: references
        )
    } catch {
        try? await connection.close()
        throw error
    }
}

private enum BlobReferenceInventoryError: Error {
    case invalidRows
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
        blobQuota: AccountBlobQuota = .conservative,
        _ body: (SQLiteAccountDatabase) async throws -> T
    ) async throws -> T {
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: author,
            blobQuota: blobQuota
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
