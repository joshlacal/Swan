import Crypto
import Foundation
import Petrel
import PetrelCrypto
import SwanCore
@testable import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class AccountDataDeletionRuntimeTests: XCTestCase {
    private let alice = "did:plc:abcdefghijklmnopqrstuvwx"
    private let bob = "did:plc:zyxwvutsrqponmlkjihgfedc"

    func testExclusiveDeletionLeaseFailsWhileAccountDatabaseIsOpen() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: alice
        )
        let deletion = try SQLiteAccountDataDeletionStore(
            dataDirectory: root
        )

        XCTAssertThrowsError(
            try deletion.acquireExclusiveLease(did: alice)
        )

        try await database.close()
        let lease = try deletion.acquireExclusiveLease(did: alice)
        try lease.destroyAccountData()
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: SQLiteLayout.accountDatabase(
                    in: root,
                    did: alice
                ).path
            )
        )
    }

    func testLifecycleLeaseIsIsolatedForDIDsSharingTheSameShard() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let (firstDID, secondDID) = twoDIDsSharingShard()
        let secondDatabase = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: secondDID
        )
        try await secondDatabase.close()
        let firstDatabase = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: firstDID
        )
        let deletion = try SQLiteAccountDataDeletionStore(
            dataDirectory: root
        )

        let secondLease = try deletion.acquireExclusiveLease(
            did: secondDID
        )
        secondLease.release()

        try await firstDatabase.close()
    }

    func testDeletionLeaseRemovesOnlyExactDIDDatabaseFamilyAndCASNamespace() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let (deletedDID, retainedDID) = twoDIDsSharingShard()
        let deletedSpace = try SpaceURI(
            authority: deletedDID,
            spaceType: "app.bsky.bookmarks",
            skey: "deletion-test"
        )
        let retainedSpace = try SpaceURI(
            authority: retainedDID,
            spaceType: "app.bsky.bookmarks",
            skey: "retained-test"
        )
        let deletedDatabase = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: deletedDID
        )
        let retainedDatabase = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: retainedDID
        )
        let sharedPayload = Data("same-cid-across-account-namespaces".utf8)
        let deletedPublic = try await deletedDatabase.put(
            sharedPayload,
            namespace: .public
        )
        let deletedSpaceOnly = try await deletedDatabase.put(
            sharedPayload,
            namespace: .space(deletedSpace)
        )
        let retainedSpaceOnly = try await retainedDatabase.put(
            sharedPayload,
            namespace: .space(retainedSpace)
        )
        XCTAssertEqual(deletedPublic.cid, deletedSpaceOnly.cid)
        XCTAssertEqual(deletedPublic.cid, retainedSpaceOnly.cid)
        let deletedPublicData = try await deletedDatabase.publicData(
            cid: deletedPublic.cid
        )
        XCTAssertEqual(deletedPublicData, sharedPayload)
        let retainedSpaceData = try await retainedDatabase.data(
            for: retainedSpaceOnly
        )
        XCTAssertEqual(retainedSpaceData, sharedPayload)
        let retainedPublicProjection = try await retainedDatabase.publicData(
            cid: retainedSpaceOnly.cid
        )
        XCTAssertNil(
            retainedPublicProjection,
            "another account's equal-CID public reference leaked space-only data"
        )

        let retainedPublicPayload = Data("retained-public-data".utf8)
        let retainedPublic = try await retainedDatabase.put(
            retainedPublicPayload,
            namespace: .public
        )
        try await deletedDatabase.close()
        try await retainedDatabase.close()
        let deletedDatabasePath = SQLiteLayout.accountDatabase(
            in: root,
            did: deletedDID
        )
        let retainedDatabasePath = SQLiteLayout.accountDatabase(
            in: root,
            did: retainedDID
        )
        let deletedCASBlob = try casBlobPath(
            root: root,
            did: deletedDID,
            cid: deletedPublic.cid
        )
        let retainedCASBlob = try casBlobPath(
            root: root,
            did: retainedDID,
            cid: retainedSpaceOnly.cid
        )
        let retainedPublicCASBlob = try casBlobPath(
            root: root,
            did: retainedDID,
            cid: retainedPublic.cid
        )
        for sidecar in ["-wal", "-shm"] {
            let url = URL(fileURLWithPath: deletedDatabasePath.path + sidecar)
            try Data(sidecar.utf8).write(to: url)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: url.path
            )
        }

        let deletion = try SQLiteAccountDataDeletionStore(
            dataDirectory: root
        )
        let lease = try deletion.acquireExclusiveLease(did: deletedDID)
        try lease.destroyAccountData()

        XCTAssertFalse(
            FileManager.default.fileExists(atPath: deletedDatabasePath.path)
        )
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: deletedDatabasePath.path + "-wal"
            )
        )
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: deletedDatabasePath.path + "-shm"
            )
        )
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: deletedCASBlob.path)
        )
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: retainedDatabasePath.path)
        )
        XCTAssertTrue(
            FileManager.default.fileExists(atPath: retainedCASBlob.path)
        )
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: retainedPublicCASBlob.path
            )
        )

        let reopenedRetained = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: retainedDID
        )
        do {
            let reopenedSpaceData = try await reopenedRetained.data(
                for: retainedSpaceOnly
            )
            XCTAssertEqual(reopenedSpaceData, sharedPayload)
            let reopenedPublicProjection =
                try await reopenedRetained.publicData(
                    cid: retainedSpaceOnly.cid
                )
            XCTAssertNil(
                reopenedPublicProjection,
                "deleting another account promoted a space-only CID"
            )
            let reopenedPublicData = try await reopenedRetained.publicData(
                cid: retainedPublic.cid
            )
            XCTAssertEqual(reopenedPublicData, retainedPublicPayload)
            try await reopenedRetained.close()
        } catch {
            try? await reopenedRetained.close()
            throw error
        }
    }

    func testSymlinkedCASEntryFailsClosedWithoutTouchingTargetOrDatabase() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: alice
        )
        let blob = try await database.put(
            Data("symlink-candidate".utf8),
            namespace: .public
        )
        try await database.close()
        let blobPath = try casBlobPath(
            root: root,
            did: alice,
            cid: blob.cid
        )
        let external = root.appending(path: "external-target")
        try Data("must-survive".utf8).write(to: external)
        try FileManager.default.removeItem(at: blobPath)
        try FileManager.default.createSymbolicLink(
            at: blobPath,
            withDestinationURL: external
        )

        let deletion = try SQLiteAccountDataDeletionStore(
            dataDirectory: root
        )
        let lease = try deletion.acquireExclusiveLease(did: alice)
        XCTAssertThrowsError(try lease.destroyAccountData())

        XCTAssertEqual(
            try Data(contentsOf: external),
            Data("must-survive".utf8)
        )
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: SQLiteLayout.accountDatabase(
                    in: root,
                    did: alice
                ).path
            )
        )
    }

    func testDeletionProcessesMoreThanTwoBoundedCASInventoryBatches() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: alice
        )
        _ = try await database.put(
            Data("seed-private-cas".utf8),
            namespace: .public
        )
        try await database.close()

        let accountDatabase = SQLiteLayout.accountDatabase(
            in: root,
            did: alice
        )
        let shard = accountDatabase
            .deletingLastPathComponent()
            .appending(path: "permissioned-blob-cas")
            .appending(
                path: Hex.encode(SHA256.hash(data: Data(alice.utf8)))
            )
            .appending(path: "aa")
        try FileManager.default.createDirectory(
            at: shard,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: shard.path
        )
        for index in 0 ..< 600 {
            let suffix = String(index, radix: 16)
            let digest =
                String(repeating: "0", count: 64 - suffix.count) + suffix
            let file = shard.appending(path: "\(digest).blob")
            try Data().write(to: file)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: file.path
            )
        }

        let deletion = try SQLiteAccountDataDeletionStore(
            dataDirectory: root
        )
        let lease = try deletion.acquireExclusiveLease(did: alice)
        try lease.destroyAccountData()

        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: shard.deletingLastPathComponent().path
            )
        )
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: accountDatabase.path)
        )
    }

    private func casBlobPath(
        root: URL,
        did: String,
        cid: String
    ) throws -> URL {
        let parsed = try CID.parse(cid)
        let digest = Hex.encode(parsed.multihash.digest)
        let accountDatabase = SQLiteLayout.accountDatabase(
            in: root,
            did: did
        )
        return accountDatabase
            .deletingLastPathComponent()
            .appending(path: "permissioned-blob-cas")
            .appending(
                path: Hex.encode(SHA256.hash(data: Data(did.utf8)))
            )
            .appending(path: String(digest.prefix(2)))
            .appending(path: "\(digest).blob")
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "swan-account-data-deletion-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }

    private func twoDIDsSharingShard() -> (String, String) {
        let alphabet = Array("abcdefghijklmnopqrstuvwxyz234567")
        var firstByPrefix: [String: String] = [:]
        for value in 0 ..< 1_024 {
            var remainder = value
            var identifier = Array(repeating: Character("a"), count: 24)
            for index in stride(from: identifier.count - 1, through: 0, by: -1) {
                identifier[index] = alphabet[remainder % alphabet.count]
                remainder /= alphabet.count
                if remainder == 0 { break }
            }
            let did = "did:plc:\(String(identifier))"
            let digest = Hex.encode(
                SHA256.hash(data: Data(did.utf8))
            )
            let prefix = String(digest.prefix(2))
            if let first = firstByPrefix[prefix], first != did {
                return (first, did)
            }
            firstByPrefix[prefix] = did
        }
        XCTFail("failed to find deterministic account-shard collision")
        return (
            "did:plc:abcdefghijklmnopqrstuvwx",
            "did:plc:bcdefghijklmnopqrstuvwxy"
        )
    }
}
