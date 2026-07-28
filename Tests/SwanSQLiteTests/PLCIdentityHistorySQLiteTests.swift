import Crypto
import Foundation
import SwanAccounts
import SwanCore
@testable import SwanSQLite
import SwanStorage
import XCTest

final class PLCIdentityHistorySQLiteTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"

    func testHistoryIsLinearIdempotentAndSurvivesRestart() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let entries = try historyEntries()
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)

        let installedGenesis = try await database.installPublicPLCOperation(entries.0)
        XCTAssertEqual(installedGenesis, entries.0)
        let installedRotation = try await database.installPublicPLCOperation(entries.1)
        XCTAssertEqual(installedRotation, entries.1)
        let replayedRotation = try PublicPLCOperationHistoryEntry(
            cid: entries.1.cid,
            previousCID: entries.1.previousCID,
            canonicalJSON: entries.1.canonicalJSON,
            createdAt: Date(timeIntervalSince1970: 1_850_000_002),
            signingKeyGeneration: entries.1.signingKeyGeneration,
            rotationKeyGeneration: entries.1.rotationKeyGeneration
        )
        let repeatedRotation = try await database.installPublicPLCOperation(
            replayedRotation
        )
        XCTAssertEqual(repeatedRotation, entries.1)

        let conflicting = try PublicPLCOperationHistoryEntry(
            cid: entries.1.cid,
            previousCID: entries.1.previousCID,
            canonicalJSON: Data([0x7b, 0x7d]),
            createdAt: entries.1.createdAt,
            signingKeyGeneration: entries.1.signingKeyGeneration,
            rotationKeyGeneration: entries.1.rotationKeyGeneration
        )
        do {
            _ = try await database.installPublicPLCOperation(conflicting)
            XCTFail("a conflicting operation body must be rejected")
        } catch let error as SwanError {
            guard case .conflict = error else {
                XCTFail("unexpected Swan error: \(error)")
                return
            }
        }

        let history = try await database.publicPLCOperationHistory()
        XCTAssertEqual(history, [entries.0, entries.1])
        try await database.close()

        let reopened = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let reloaded = try await reopened.publicPLCOperationHistory()
        XCTAssertEqual(reloaded, [entries.0, entries.1])
        try await reopened.close()
    }

    private func historyEntries() throws -> (
        PublicPLCOperationHistoryEntry,
        PublicPLCOperationHistoryEntry
    ) {
        let signing = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 31, count: 32)
        )
        let rotation = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 37, count: 32)
        )
        let genesisUnsigned = try PLCATProfile.regularOperation(
            handle: "alice.example.com",
            signingPublicKey: signing.publicKey,
            rotationPublicKeys: [rotation.publicKey],
            pdsOrigin: URL(string: "https://pds.example.com")!,
            prev: nil
        )
        let genesis = try PLCOperationCodec.sign(.regular(genesisUnsigned), using: rotation)
        let nextSigning = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 41, count: 32)
        )
        let nextRotation = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 43, count: 32)
        )
        let rotationUnsigned = try PLCATProfile.regularOperation(
            handle: "alice.example.com",
            signingPublicKey: nextSigning.publicKey,
            rotationPublicKeys: [nextRotation.publicKey],
            pdsOrigin: URL(string: "https://pds.example.com")!,
            prev: try genesis.cid.string
        )
        let rotated = try PLCOperationCodec.sign(.regular(rotationUnsigned), using: rotation)
        return (
            try PublicPLCOperationHistoryEntry(
                cid: try genesis.cid.string,
                previousCID: nil,
                canonicalJSON: try genesis.canonicalJSON,
                createdAt: Date(timeIntervalSince1970: 1_750_000_001),
                signingKeyGeneration: 1,
                rotationKeyGeneration: 1
            ),
            try PublicPLCOperationHistoryEntry(
                cid: try rotated.cid.string,
                previousCID: try genesis.cid.string,
                canonicalJSON: try rotated.canonicalJSON,
                createdAt: Date(timeIntervalSince1970: 1_750_000_002),
                signingKeyGeneration: 2,
                rotationKeyGeneration: 2
            )
        )
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPLCIdentityHistoryTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }
}
