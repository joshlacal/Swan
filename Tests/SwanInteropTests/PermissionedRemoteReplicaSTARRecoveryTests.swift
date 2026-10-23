import Crypto
import Foundation
import Petrel
import PetrelCrypto
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanSQLite
import SwanStorage
@testable import SwanInterop
import XCTest

final class PermissionedRemoteReplicaSTARRecoveryTests: XCTestCase {
    func testNativeSTARPublishesAndReplacementRemovesAbsentRecords() async throws {
        let fixture = try NativeSTARFixture()
        let root = FileManager.default.temporaryDirectory.appending(path: "SwanSTARRecovery-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: fixture.target.receiverDID)
        let orchestrator = PermissionedRemoteReplicaRecoveryOrchestrator(
            database: database, now: { 100 }, publicationAuthorization: { try await $0() }
        )
        do {
            let first = try fixture.archive(keys: ["aa", "b"], revision: "222222222222a")
            let result = try await orchestrator.recover(
                target: fixture.target, requestID: "native-star-initial", source: fixture.session(first),
                profileID: "permissioned-data-0016-2026-10-22", expiresAt: 200
            )
            XCTAssertEqual(result.recordCount, 2)
            XCTAssertEqual(result.uniqueBlockCount, 1, "shared CIDs retain one durable body")
            let firstValue = try await database.permissionedRemoteReplicaRecord(target: fixture.target, collection: "app.bsky.feed.post", rkey: "aa")
            XCTAssertEqual(firstValue, fixture.recordBytes)
            let replacement = try fixture.archive(keys: ["b"], revision: "222222222222b")
            let replaced = try await orchestrator.recover(
                target: fixture.target, requestID: "native-star-replace", source: fixture.session(replacement),
                profileID: "permissioned-data-0016-2026-10-22", expiresAt: 200
            )
            XCTAssertEqual(replaced.recordCount, 1)
            XCTAssertGreaterThan(replaced.head.generation, result.head.generation)
            let removed = try await database.permissionedRemoteReplicaRecord(target: fixture.target, collection: "app.bsky.feed.post", rkey: "aa")
            let retained = try await database.permissionedRemoteReplicaRecord(target: fixture.target, collection: "app.bsky.feed.post", rkey: "b")
            XCTAssertNil(removed)
            XCTAssertEqual(retained, fixture.recordBytes)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testCorruptSTARCannotReplaceDurableHead() async throws {
        let fixture = try NativeSTARFixture()
        let root = FileManager.default.temporaryDirectory.appending(path: "SwanSTARRecoveryCorrupt-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: fixture.target.receiverDID)
        let orchestrator = PermissionedRemoteReplicaRecoveryOrchestrator(
            database: database, now: { 100 }, publicationAuthorization: { try await $0() }
        )
        do {
            let first = try fixture.archive(keys: ["aa"], revision: "222222222222a")
            let original = try await orchestrator.recover(
                target: fixture.target, requestID: "native-star-good", source: fixture.session(first),
                profileID: "permissioned-data-0016-2026-10-22", expiresAt: 200
            )
            let next = try fixture.archive(keys: ["b"], revision: "222222222222b")
            var corrupted = next.bytes
            corrupted[corrupted.count - 1] ^= 1
            do {
                _ = try await orchestrator.recover(
                    target: fixture.target, requestID: "native-star-corrupt", source: fixture.session(next, bytes: corrupted),
                    profileID: "permissioned-data-0016-2026-10-22", expiresAt: 200
                )
                XCTFail("corrupt archive must not publish")
            } catch { XCTAssertEqual(error as? SpaceSTARError, .digestMismatch) }
            let head = try await database.permissionedRemoteReplicaHead(target: fixture.target)
            XCTAssertEqual(head, original.head)
            let unexpected = try await database.permissionedRemoteReplicaRecord(target: fixture.target, collection: "app.bsky.feed.post", rkey: "b")
            XCTAssertNil(unexpected)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testBadMACFailsBeforePublicationAndKeepsNoHead() async throws {
        let fixture = try NativeSTARFixture()
        let root = FileManager.default.temporaryDirectory.appending(path: "SwanSTARBadMAC-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: fixture.target.receiverDID)
        let orchestrator = PermissionedRemoteReplicaRecoveryOrchestrator(
            database: database, now: { 100 }, publicationAuthorization: { _ in XCTFail("bad MAC reached publication"); throw SpaceSTARError.badMAC }
        )
        let archive = try fixture.archive(keys: ["a"], revision: "222222222222a")
        do {
            _ = try await orchestrator.recover(
                target: fixture.target, requestID: "native-star-bad-mac", source: fixture.session(archive, invalidMAC: true),
                profileID: "permissioned-data-0016-2026-10-22", expiresAt: 200
            )
            XCTFail("bad MAC accepted")
        } catch { XCTAssertEqual(error as? SpaceMAC.Failure, .mismatch) }
        let head = try await database.permissionedRemoteReplicaHead(target: fixture.target)
        XCTAssertNil(head)
        try await database.close()
    }
}

private struct NativeSTARFixture {
    let target: PermissionedRemoteReplicaTarget
    let kemKey: P256.KeyAgreement.PrivateKey
    let kemDIDKey: String
    let recordBytes = Data([0xa1, 0x61, 0x78, 0x01])

    init() throws {
        target = try PermissionedRemoteReplicaTarget(
            receiverDID: "did:plc:receiverabcdefghijkl", space: SpaceURI("at://did:plc:authorityabcdefghijk/space/app.swan.test/star"),
            repositoryDID: "did:plc:repositoryabcdefghij"
        )
        kemKey = P256.KeyAgreement.PrivateKey()
        kemDIDKey = try P256DIDKey(publicKey: P256.Signing.PublicKey(compressedRepresentation: kemKey.publicKey.compressedRepresentation)).value
    }

    struct Archive { let commit: SpaceRepositoryCommit; let bytes: Data }

    func archive(keys: [String], revision: String) throws -> Archive {
        var hash = LtHash()
        let cid = CID.fromDAGCBOR(recordBytes)
        let records = try keys.map { key in
            hash.add(element: "app.bsky.feed.post/\(key)/\(cid.string)")
            return SpaceRecord(
                uri: try SpaceRecordURI(space: target.space, author: target.repositoryDID, collection: "app.bsky.feed.post", rkey: key),
                value: recordBytes, cid: cid.string, revision: 0
            )
        }
        let commit = try SpaceRepositoryCommit(repo: target.repositoryDID, space: target.space, rev: revision, data: hash.commitment)
        return Archive(commit: commit, bytes: try SpaceSTARCodec.encode(commit: commit, records: records))
    }

    func session(_ archive: Archive, bytes: Data? = nil, invalidMAC: Bool = false) throws -> PermissionedRemoteReplicaSourceSession {
        let exchange = try SpaceMAC.encapsulate(authorKey: kemDIDKey)
        let secret = try SpaceMAC.decapsulate(privateKey: kemKey, keyShare: exchange.keyShare)
        return try PermissionedRemoteReplicaSourceSession(
            identity: PermissionedRemoteReplicaSourceIdentity(
                origin: URL(string: "https://writer.example")!, repositoryDID: target.repositoryDID,
                verifierIdentity: PermissionedSpaceMACRequest.verifierIdentity(authorKEMKey: kemDIDKey)
            ),
            authorKEMKey: kemDIDKey, sharedSecret: exchange.sharedSecret,
            mac: invalidMAC ? Data(repeating: 0, count: 32) : archive.commit.mac(sharedSecret: secret),
            freshnessWitness: PermissionedRemoteReplicaFreshnessWitness(wireRevision: TID(tidString: archive.commit.rev), commitment: archive.commit.data),
            source: STARRecoveryTestSource(bytes: bytes ?? archive.bytes), closeSource: {}
        )
    }
}

private actor STARRecoveryTestSource: SpaceCARRecoveryByteSource {
    let bytes: Data
    var offset = 0
    init(bytes: Data) { self.bytes = bytes }
    func read(maximumBytes: Int) async throws -> Data? {
        guard offset < bytes.count else { return nil }
        let length = min(maximumBytes, 7, bytes.count - offset)
        defer { offset += length }
        return Data(bytes[offset..<offset + length])
    }
}
