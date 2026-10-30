import Crypto
import Foundation
import Hummingbird
import HummingbirdTesting
import Logging
import NIOCore
import Petrel
import PetrelRepo
import SwanCore
import SwanHTTP
import SwanOAuth
import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

/// Upstream atproto 907f41a7 requires a current public record reference before
/// sync.getBlob serves a payload. Retained CAS namespace edges are not enough.
final class PermissionedBlobPublicReadTests: XCTestCase, @unchecked Sendable {
    private static let did = "did:plc:abcdefghijklmnopqrstuvwx"

    func testPublicGetBlobRejectsStagedPermissionedOnlyAndOrphanedPublicBlobs() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        let staged = try await fixture.database.putBlob(
            Data("uncommitted upload".utf8), namespace: .staged
        )
        let privateBytes = Data("permissioned attachment".utf8)
        let privateBlob = try await fixture.database.putBlob(
            privateBytes, namespace: .staged, mimeType: "application/octet-stream"
        )
        try await fixture.attachToSpace(cid: privateBlob.cid, size: privateBytes.count)
        let orphan = try await fixture.database.putBlob(
            Data("retained legacy public edge".utf8), namespace: .public
        )

        let app = fixture.server.buildApplication(logger: Logger(label: #function))
        try await app.test(.router) { client in
            for cid in [staged.cid, privateBlob.cid, orphan.cid] {
                try await client.execute(uri: fixture.uri(cid), method: .get) { response in
                    XCTAssertEqual(response.status, .notFound)
                    let error = try JSONSerialization.jsonObject(with: Data(buffer: response.body))
                        as? [String: String]
                    XCTAssertEqual(error?["error"], "BlobNotFound")
                }
            }
        }
        try await fixture.assertPermissionedBytes(privateBytes, cid: privateBlob.cid)
    }

    func testSharedBlobStopsBeingPublicWhenLastPublicReferenceIsRemoved() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        let bytes = Data("shared public and permissioned attachment".utf8)
        let blob = try await fixture.database.putBlob(
            bytes, namespace: .staged, mimeType: "application/octet-stream"
        )
        let first = try PublicRepositoryPath(collection: "app.bsky.feed.post", recordKey: "first")
        let last = try PublicRepositoryPath(collection: "app.bsky.feed.post", recordKey: "last")
        let record = try PublicBlobReadTestRepository.record(cid: blob.cid, size: bytes.count)
        try await fixture.repository.commit([
            .create(path: first, record: record),
            .create(path: last, record: record),
        ])
        try await fixture.attachToSpace(cid: blob.cid, size: bytes.count)

        guard case let .active(target) = try await fixture.directory.publicRepositoryBlobOutcome(
            did: Self.did
        ) else { return XCTFail("expected preopened blob read target") }
        let initialMetadata = try await target.store.publicBlobMetadata(cid: blob.cid)
        XCTAssertEqual(initialMetadata?.size, bytes.count)

        let app = fixture.server.buildApplication(logger: Logger(label: #function))
        try await app.test(.router) { client in
            try await client.execute(uri: fixture.uri(blob.cid), method: .get) { response in
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(Data(buffer: response.body), bytes)
            }
            try await fixture.repository.commit([.delete(path: first, expectedRecordCID: nil)])
            try await client.execute(uri: fixture.uri(blob.cid), method: .get) { response in
                XCTAssertEqual(response.status, .ok, "the other public reference still publishes this CID")
                XCTAssertEqual(Data(buffer: response.body), bytes)
            }
            try await fixture.repository.commit([
                .update(
                    path: last,
                    record: ["$type": .string("app.bsky.feed.post"), "text": .string("attachment removed")],
                    expectedRecordCID: nil
                ),
            ])
            // The edge remains for deferred GC, so this assertion distinguishes
            // current record reachability from namespace-only checks.
            let retainedEdge = try await fixture.database.publicBlobExists(cid: blob.cid)
            XCTAssertTrue(retainedEdge)
            try await client.execute(uri: fixture.uri(blob.cid), method: .get) { response in
                XCTAssertEqual(response.status, .notFound)
                let error = try JSONSerialization.jsonObject(with: Data(buffer: response.body))
                    as? [String: String]
                XCTAssertEqual(error?["error"], "BlobNotFound")
            }
        }
        // A previously resolved capability must also recheck both entry points.
        let staleMetadata = try await target.store.publicBlobMetadata(cid: blob.cid)
        let staleBody = try await target.store.publicBlob(cid: blob.cid)
        XCTAssertNil(staleMetadata)
        XCTAssertNil(staleBody)
        try await fixture.assertPermissionedBytes(bytes, cid: blob.cid)
    }

    func testDeletingLastPublicRecordRevokesBlobBeforeGarbageCollection() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { await fixture.close() }
        let bytes = Data("public attachment before deletion".utf8)
        let blob = try await fixture.database.putBlob(
            bytes, namespace: .staged, mimeType: "application/octet-stream"
        )
        let path = try PublicRepositoryPath(collection: "app.bsky.feed.post", recordKey: "deleted")
        try await fixture.repository.commit([
            .create(path: path, record: try PublicBlobReadTestRepository.record(cid: blob.cid, size: bytes.count)),
        ])
        try await fixture.repository.commit([.delete(path: path, expectedRecordCID: nil)])
        let retainedEdge = try await fixture.database.publicBlobExists(cid: blob.cid)
        XCTAssertTrue(retainedEdge)
        let app = fixture.server.buildApplication(logger: Logger(label: #function))
        try await app.test(.router) { client in
            try await client.execute(uri: fixture.uri(blob.cid), method: .get) { response in
                XCTAssertEqual(response.status, .notFound)
                let error = try JSONSerialization.jsonObject(with: Data(buffer: response.body))
                    as? [String: String]
                XCTAssertEqual(error?["error"], "BlobNotFound")
            }
        }
    }

    private struct Fixture: Sendable {
        let root: URL
        let control: SQLiteControlDatabase
        let directory: SQLitePreMigratedAccountDirectory
        let database: SQLiteAccountDatabase
        let repository: PublicBlobReadTestRepository
        let server: SwanHTTPServer
        let space: SpaceURI

        static func make() async throws -> Self {
            let root = FileManager.default.temporaryDirectory
                .appending(path: "PermissionedBlobPublicReadTests-\(UUID().uuidString)")
            let control = try await SQLiteControlDatabase(dataDirectory: root)
            let seed = try await SQLiteAccountDatabase(dataDirectory: root, did: PermissionedBlobPublicReadTests.did)
            try await seed.close()
            _ = try await control.createAccount(try AccountControlRegistration(
                did: PermissionedBlobPublicReadTests.did,
                canonicalHandle: "blob-reader.example.com",
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: AccountControlKeyReference(purpose: .signing, generation: 1),
                rotationKey: AccountControlKeyReference(purpose: .rotation, generation: 1),
                publicGenesisCommitCID: nil,
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            ))
            let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
                dataDirectory: root, controlStore: control, publicIdentityVerifier: nil
            )
            let store = await directory.preopenedPublicMutationStore(did: PermissionedBlobPublicReadTests.did)
            let database = try XCTUnwrap(store as? SQLiteAccountDatabase)
            let repository = try await PublicBlobReadTestRepository.install(
                database: database, did: PermissionedBlobPublicReadTests.did
            )
            let runtime = try SwanOAuthRuntime(controlStore: control, serverKey: Data(repeating: 0x41, count: 32))
            let profile = try ProtocolProfile.load(from: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
                .appending(path: "Profiles/permissioned-data-0016-2026-10-01.json"))
            let server = SwanHTTPServer(
                profile: profile,
                configuration: .init(publicURL: URL(string: "https://swan.example")!),
                oauthRuntime: runtime,
                accountControlStore: control,
                publicRepositoryReadDirectory: directory
            )
            return Self(
                root: root, control: control, directory: directory, database: database,
                repository: repository, server: server,
                space: try SpaceURI(authority: PermissionedBlobPublicReadTests.did, spaceType: "app.swan.private", skey: "blobs")
            )
        }

        func uri(_ cid: String) -> String {
            "/xrpc/com.atproto.sync.getBlob?did=\(PermissionedBlobPublicReadTests.did)&cid=\(cid)"
        }

        func attachToSpace(cid: String, size: Int) async throws {
            let record = try DAGCBOR.encodeValue(OrderedCBORMap(entries: [
                (key: "$type", value: "app.bsky.feed.post"),
                (key: "blob", value: OrderedCBORMap(entries: [
                    (key: "$type", value: "blob"),
                    (key: "ref", value: ATProtoLink(cid: try CID.parse(cid))),
                    (key: "mimeType", value: "application/octet-stream"),
                    (key: "size", value: size),
                ])),
            ]))
            _ = try await database.apply(
                space: space, author: PermissionedBlobPublicReadTests.did, expectedRevision: 0,
                requestID: UUID(), wireRevision: try TID(tidString: "2222222222222"),
                writes: [.create(
                    uri: try SpaceRecordURI(space: space, author: PermissionedBlobPublicReadTests.did,
                        collection: "app.bsky.feed.post", rkey: "attachment"),
                    value: record, cid: CID.fromDAGCBOR(record).string
                )]
            )
        }

        func assertPermissionedBytes(_ expected: Data, cid: String) async throws {
            let result = try await database.permissionedBlob(space: space, author: PermissionedBlobPublicReadTests.did, cid: cid)
            let blob = try XCTUnwrap(result)
            var bytes = Data()
            try await blob.body.streamBody(maximumChunkBytes: 7) { bytes.append($0) }
            XCTAssertEqual(bytes, expected)
        }

        func close() async {
            try? await directory.close()
            try? await control.close()
            try? FileManager.default.removeItem(at: root)
        }
    }
}

/// Shared with the real-directory registration regression: a namespace edge
/// alone no longer represents an anonymously readable, published attachment.
struct PublicBlobReadTestRepository: Sendable {
    let database: SQLiteAccountDatabase
    let did: String
    let key: P256.Signing.PrivateKey

    static func install(database: SQLiteAccountDatabase, did: String) async throws -> Self {
        let key = P256.Signing.PrivateKey()
        let genesis = try PublicRepositoryGenesisCodec.create(did: did, revision: "3jzfcijpj2z2a", signingKey: key)
        _ = try await database.installPublicRepositoryGenesis(
            genesis, signingPublicKey: key.publicKey, installedAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
        return Self(database: database, did: did, key: key)
    }

    static func record(cid: String, size: Int, mimeType: String = "application/octet-stream") throws -> PublicRecord {
        ["$type": .string("app.bsky.feed.post"), "blob": .object([
            "$type": .string("blob"), "ref": .link(try CID.parse(cid)),
            "mimeType": .string(mimeType), "size": .integer(size),
        ])]
    }

    func commit(_ writes: [PublicRepositoryWrite]) async throws {
        let loaded = try await database.loadPublicRepositoryState()
        let current = try XCTUnwrap(loaded)
        let requestID = UUID().uuidString
        let request = try PublicRepositoryMutationRequest(
            id: requestID, canonicalDigest: Data(SHA256.hash(data: Data(requestID.utf8))), baseCommitCID: current.commitCID
        )
        guard case let .reserved(reservation) = try await database.reservePublicRepositoryRevision(
            request, wallClockMicroseconds: UInt64(Date().timeIntervalSince1970 * 1_000_000)
        ) else { throw PublicRepositoryMutationStoreError.conflictingRequestReuse }
        let prepared = try await PublicRepositoryEngine.apply(
            repositoryDID: did, currentState: current, blocks: database, revision: reservation.nextRevision,
            batch: try PublicRepositoryWriteBatch(writes: writes, expectedCommitCID: current.commitCID),
            signer: P256PublicRepositoryCommitSigner(privateKey: key)
        )
        _ = try await database.applyPublicRepositoryMutation(reservation: reservation, prepared: prepared)
    }
}
