import Foundation
import SQLiteNIO
@testable import SwanSQLite
import SwanStorage
import XCTest

final class PLCAccountPreparationSQLiteTests: XCTestCase {
    func testControlIntentAndAccountJournalSurviveIndependentRestarts() async throws {
        let root = try privateTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let intent = try sampleIntent(did: did)
        let journal = try sampleJournal(did: did)

        var control: SQLiteControlDatabase? = try await SQLiteControlDatabase(dataDirectory: root)
        let initialReservation = try await control!.reservePLCAccountPreparationIntent(intent)
        XCTAssertEqual(initialReservation, .created)
        var account: SQLiteAccountDatabase? = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: did
        )
        let initialJournal = try await account!.installPLCAccountPreparationJournal(journal)
        XCTAssertEqual(initialJournal, journal)
        try await account!.close()
        try await control!.close()
        account = nil
        control = nil

        control = try await SQLiteControlDatabase(dataDirectory: root)
        account = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let reloadedIntent = try await control!
            .plcAccountPreparationIntent(requestID: intent.requestID)
        let reloadedJournal = try await account!.plcAccountPreparationJournal()
        let registeredAccount = try await control!.account(did: did)
        let safeControlSchema = try await schemaContainsNoSecretColumns(
            connection: control!.connection,
            table: "plc_account_preparation_intents"
        )
        let safeAccountSchema = try await schemaContainsNoSecretColumns(
            connection: account!.connection,
            table: "plc_account_preparation_journal"
        )
        XCTAssertEqual(reloadedIntent, intent)
        XCTAssertEqual(reloadedJournal, journal)
        XCTAssertNil(registeredAccount)
        XCTAssertTrue(safeControlSchema)
        XCTAssertTrue(safeAccountSchema)
        try await account!.close()
        try await control!.close()
    }

    func testStagesAreCASMonotonicAndImmutableReplayIsExact() async throws {
        let root = try privateTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        let account = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let intent = try sampleIntent(did: did)
        let journal = try sampleJournal(did: did)

        let created = try await control.reservePLCAccountPreparationIntent(intent)
        let replayed = try await control.reservePLCAccountPreparationIntent(intent)
        XCTAssertEqual(created, .created)
        XCTAssertEqual(replayed, .existing(intent))
        _ = try await account.installPLCAccountPreparationJournal(journal)
        let commitCID = "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        let advancedIntent = try await control.advancePLCAccountPreparationIntent(
            requestID: intent.requestID,
            expectedStage: .keysStored,
            to: .repositoryInstalled
        )
        let advancedJournal = try await account.advancePLCAccountPreparationJournal(
            requestID: intent.requestID,
            expectedStage: .keysStored,
            to: .repositoryInstalled,
            publicGenesisCommitCID: commitCID
        )
        XCTAssertEqual(advancedIntent.stage, .repositoryInstalled)
        XCTAssertEqual(advancedJournal.publicGenesisCommitCID, commitCID)
        await XCTAssertThrowsErrorAsync(
            try await control.advancePLCAccountPreparationIntent(
                requestID: intent.requestID,
                expectedStage: .repositoryInstalled,
                to: .keysStored
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await account.advancePLCAccountPreparationJournal(
                requestID: intent.requestID,
                expectedStage: .repositoryInstalled,
                to: .keysStored,
                publicGenesisCommitCID: commitCID
            )
        )
        try await account.close()
        try await control.close()
    }

    private func sampleIntent(did: String) throws -> PLCAccountPreparationIntent {
        try PLCAccountPreparationIntent(
            requestID: "sqlite-restart",
            did: did,
            canonicalHandle: "sqlite.example.com",
            pdsOrigin: "https://pds.example.com",
            repositoryRevision: "3lqby3xuo4k2a",
            operationCID: "bafyreigbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            stage: .keysStored
        )
    }

    private func sampleJournal(did: String) throws -> PLCAccountPreparationJournal {
        try PLCAccountPreparationJournal(
            requestID: "sqlite-restart",
            did: did,
            canonicalHandle: "sqlite.example.com",
            pdsOrigin: "https://pds.example.com",
            repositoryRevision: "3lqby3xuo4k2a",
            operationCID: "bafyreigbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            signedOperationJSON: Data("{\"public\":\"operation\"}".utf8),
            signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
            rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
            publicGenesisCommitCID: nil,
            stage: .keysStored
        )
    }
}

private func privateTemporaryDirectory() throws -> URL {
    let root = FileManager.default.temporaryDirectory
        .appending(path: "SwanPLCPreparationSQLite-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
        at: root,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    return root
}

private func schemaContainsNoSecretColumns(
    connection: SQLiteConnection,
    table: String
) async throws -> Bool {
    let rows = try await connection.query("PRAGMA table_info(\(table))")
    let names = rows.compactMap { $0.column("name")?.string?.lowercased() }
    guard !names.isEmpty else { return false }
    for forbidden in ["password", "verifier", "private_key", "access_token", "session", " car"] {
        if names.contains(where: { $0.contains(forbidden) }) { return false }
    }
    return true
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected error", file: file, line: line)
    } catch {}
}
