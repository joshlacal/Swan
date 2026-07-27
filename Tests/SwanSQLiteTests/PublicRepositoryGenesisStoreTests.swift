import Crypto
import Foundation
import SQLiteNIO
import SwanPublicRepository
@testable import SwanSQLite
import XCTest

final class PublicRepositoryGenesisStoreTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let revision = "3jzfcijpj2z2a"

    func testInstallIsImmutableAndReopenRevalidatesStoredCAR() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let genesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: revision,
            signingKey: key
        )

        let first = try await database.installPublicRepositoryGenesis(
            genesis,
            signingPublicKey: key.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_750_000_000.123456)
        )
        let repeated = try await database.installPublicRepositoryGenesis(
            genesis,
            signingPublicKey: key.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_750_000_100)
        )
        let divergent = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: "3jzfcijpj2z2b",
            signingKey: key
        )

        XCTAssertFalse(first.wasAlreadyInstalled)
        XCTAssertTrue(repeated.wasAlreadyInstalled)
        XCTAssertEqual(repeated.persisted, first.persisted)
        await XCTAssertThrowsAsync(
            try await database.installPublicRepositoryGenesis(
                divergent,
                signingPublicKey: key.publicKey,
                installedAt: Date(timeIntervalSince1970: 1_750_000_200)
            )
        ) { error in
            XCTAssertEqual(error as? PublicRepositoryGenesisStoreError, .conflictingGenesis)
        }
        try await database.close()

        let reopened = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let maybeLoaded = try await reopened.loadPublicRepositoryGenesis(
            did: did,
            signingPublicKey: key.publicKey
        )
        let loaded = try XCTUnwrap(maybeLoaded)
        XCTAssertEqual(loaded, first.persisted)
        try await reopened.close()
    }

    func testTamperedStoredPublicGenesisFailsClosed() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = P256.Signing.PrivateKey()
        let database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let genesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: revision,
            signingKey: key
        )
        _ = try await database.installPublicRepositoryGenesis(
            genesis,
            signingPublicKey: key.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
        try await database.close()

        let raw = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.accountDatabase(in: root, did: did).path)
        )
        _ = try await raw.query(
            "UPDATE public_repository_genesis SET car = ?",
            [Data([0x00]).sqliteData!]
        )
        try await raw.close()

        let reopened = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        await XCTAssertThrowsAsync(
            try await reopened.loadPublicRepositoryGenesis(
                did: did,
                signingPublicKey: key.publicKey
            )
        ) { error in
            XCTAssertEqual(error as? PublicRepositoryGenesisStoreError, .corruptStoredGenesis)
        }
        try await reopened.close()
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPublicRepositoryGenesisStoreTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        return root
    }
}

private func XCTAssertThrowsAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ handler: (any Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("expected error", file: file, line: line)
    } catch {
        handler(error)
    }
}
