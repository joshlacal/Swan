import Crypto
import Foundation
import SQLiteNIO
import SwanAccounts
@testable import SwanSQLite
import SwanStorage
import XCTest

final class PLCAccountPreparationSQLiteTests: XCTestCase {
    func testControlIntentAndTypedJournalSurviveIndependentRestarts() async throws {
        let root = try privateTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let sample = try preparationSample()

        var control: SQLiteControlDatabase? = try await SQLiteControlDatabase(dataDirectory: root)
        let reservation = try await control!.reservePLCAccountPreparationIntent(sample.intent)
        XCTAssertEqual(reservation, .created)
        var account: SQLiteAccountDatabase? = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: sample.did
        )
        let installed = try await account!.installPLCAccountPreparationJournal(sample.journal)
        XCTAssertEqual(installed, sample.journal)
        try await account!.close()
        try await control!.close()
        account = nil
        control = nil

        control = try await SQLiteControlDatabase(dataDirectory: root)
        account = try await SQLiteAccountDatabase(dataDirectory: root, did: sample.did)
        let reloadedIntent = try await control!
            .plcAccountPreparationIntent(requestID: sample.intent.requestID)
        let reloadedJournal = try await account!.plcAccountPreparationJournal()
        let journal = try XCTUnwrap(reloadedJournal)
        let reconstructed = try PLCOperationCodec.reconstructGenesis(
            signingDIDKey: journal.operation.signingDIDKey,
            rotationDIDKey: journal.operation.rotationDIDKey,
            canonicalHandle: journal.canonicalHandle,
            pdsOrigin: journal.pdsOrigin,
            signature: journal.operation.signature
        )
        try PLCOperationCodec.verifyGenesis(reconstructed, expectedDID: sample.did)
        XCTAssertEqual(try reconstructed.cid.string, sample.intent.operationCID)
        XCTAssertEqual(reloadedIntent, sample.intent)
        XCTAssertEqual(journal, sample.journal)
        let activeAccount = try await control!.account(did: sample.did)
        XCTAssertNil(activeAccount)
        let controlConnection = await control!.connection
        let accountConnection = await account!.connection
        let schemaIsPublic = try await preparationSchemaIsPublicOnly(
            control: controlConnection,
            account: accountConnection
        )
        let valuesArePublic = try await preparationValuesArePublicOnly(
            control: controlConnection,
            account: accountConnection
        )
        XCTAssertTrue(schemaIsPublic)
        XCTAssertTrue(valuesArePublic)
        try await account!.close()
        try await control!.close()
    }

    func testStoresRejectForwardSkipsAndNonInitialInstallation() async throws {
        let root = try privateTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let sample = try preparationSample()
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        let account = try await SQLiteAccountDatabase(dataDirectory: root, did: sample.did)
        _ = try await control.reservePLCAccountPreparationIntent(sample.intent)
        _ = try await account.installPLCAccountPreparationJournal(sample.journal)
        let commitCID = "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        await XCTAssertThrowsErrorAsync(
            try await control.advancePLCAccountPreparationIntent(
                requestID: sample.intent.requestID,
                expectedStage: .keysStored,
                to: .submissionPending
            )
        )
        await XCTAssertThrowsErrorAsync(
            try await account.advancePLCAccountPreparationJournal(
                requestID: sample.intent.requestID,
                expectedStage: .keysStored,
                to: .submitted,
                publicGenesisCommitCID: commitCID
            )
        )
        let submittedIntent = try PLCAccountPreparationIntent(
            requestID: "forged-submitted",
            did: sample.did,
            canonicalHandle: sample.intent.canonicalHandle,
            pdsOrigin: sample.intent.pdsOrigin,
            repositoryRevision: sample.intent.repositoryRevision,
            operationCID: sample.intent.operationCID,
            stage: .submitted
        )
        await XCTAssertThrowsErrorAsync(
            try await control.reservePLCAccountPreparationIntent(submittedIntent)
        )
        let submittedJournal = try PLCAccountPreparationJournal(
            requestID: "forged-submitted",
            canonicalHandle: sample.journal.canonicalHandle,
            pdsOrigin: sample.journal.pdsOrigin,
            repositoryRevision: sample.journal.repositoryRevision,
            operation: sample.journal.operation,
            signingKey: sample.journal.signingKey,
            rotationKey: sample.journal.rotationKey,
            publicGenesisCommitCID: commitCID,
            stage: .submitted
        )
        await XCTAssertThrowsErrorAsync(
            try await account.installPLCAccountPreparationJournal(submittedJournal)
        )

        var intent = sample.intent
        var journal = sample.journal
        for next in [
            PLCAccountPreparationStage.repositoryInstalled,
            .submissionPending,
            .submitted,
        ] {
            intent = try await control.advancePLCAccountPreparationIntent(
                requestID: intent.requestID,
                expectedStage: intent.stage,
                to: next
            )
            journal = try await account.advancePLCAccountPreparationJournal(
                requestID: journal.requestID,
                expectedStage: journal.stage,
                to: next,
                publicGenesisCommitCID: commitCID
            )
            XCTAssertEqual(intent.stage, next)
            XCTAssertEqual(journal.stage, next)
        }
        let idempotent = try await control.advancePLCAccountPreparationIntent(
            requestID: intent.requestID,
            expectedStage: .submissionPending,
            to: .submitted
        )
        XCTAssertEqual(idempotent, intent)
        try await account.close()
        try await control.close()
    }

    func testJournalRejectsHostileSecretLikeOperationPayloads() throws {
        for hostile in [
            ("private_key=AAAA", validDIDKey(), validSignature()),
            (validDIDKey(), "password=correct-horse-battery-staple", validSignature()),
            (validDIDKey(), alternateValidDIDKey(), "access_token=Bearer-secret"),
        ] {
            XCTAssertThrowsError(
                try PLCAccountPreparationOperationFacts(
                    signingDIDKey: hostile.0,
                    rotationDIDKey: hostile.1,
                    signature: hostile.2
                )
            )
        }
    }

    func testActualPreTask14DatabasesGainPreparationTablesWithoutLosingRows() async throws {
        let root = try privateTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let accountURL = SQLiteLayout.accountDatabase(in: root, did: did)
        try FileManager.default.createDirectory(
            at: accountURL.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let legacyAccount = try await SQLiteConnection.open(storage: .file(path: accountURL.path))
        for statement in SQLiteLayout.accountMigrations
            where !statement.contains("plc_account_preparation_journal") {
            _ = try await legacyAccount.query(statement)
        }
        _ = try await legacyAccount.query(
            "INSERT INTO public_records(uri, value, revision) VALUES ('at://legacy', X'01', 1)"
        )
        try await legacyAccount.close()
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: accountURL.path
        )

        let controlURL = SQLiteLayout.controlDatabase(in: root)
        let legacyControl = try await SQLiteConnection.open(storage: .file(path: controlURL.path))
        for statement in SQLiteLayout.controlMigrations
            where !statement.contains("plc_account_preparation_intents") {
            _ = try await legacyControl.query(statement)
        }
        try await legacyControl.close()
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: controlURL.path
        )

        let account = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        let accountConnection = await account.connection
        let controlConnection = await control.connection
        let legacyRows = try await accountConnection.query(
            "SELECT uri, revision FROM public_records WHERE uri = 'at://legacy'"
        )
        XCTAssertEqual(legacyRows.first?.column("revision")?.integer, 1)
        let accountTableExists = try await tableExists(
            connection: accountConnection,
            table: "plc_account_preparation_journal"
        )
        let controlTableExists = try await tableExists(
            connection: controlConnection,
            table: "plc_account_preparation_intents"
        )
        XCTAssertTrue(accountTableExists)
        XCTAssertTrue(controlTableExists)
        try await account.close()
        try await control.close()
    }
}

private struct PreparationSample {
    let did: String
    let intent: PLCAccountPreparationIntent
    let journal: PLCAccountPreparationJournal
}

private func preparationSample() throws -> PreparationSample {
    let signingKey = P256.Signing.PrivateKey()
    let rotationKey = P256.Signing.PrivateKey()
    let unsigned = try PLCATProfile.regularOperation(
        handle: "sqlite.example.com",
        signingPublicKey: signingKey.publicKey,
        rotationPublicKeys: [rotationKey.publicKey],
        pdsOrigin: URL(string: "https://pds.example.com")!,
        prev: nil
    )
    let operation = try PLCOperationCodec.sign(.regular(unsigned), using: rotationKey)
    let regular = try XCTUnwrap(operation.regular)
    let did = try PLCOperationCodec.genesisDID(for: operation)
    let intent = try PLCAccountPreparationIntent(
        requestID: "sqlite-restart",
        did: did,
        canonicalHandle: "sqlite.example.com",
        pdsOrigin: "https://pds.example.com",
        repositoryRevision: "3lqby3xuo4k2a",
        operationCID: try operation.cid.string,
        stage: .keysStored
    )
    let journal = try PLCAccountPreparationJournal(
        requestID: intent.requestID,
        canonicalHandle: intent.canonicalHandle,
        pdsOrigin: intent.pdsOrigin,
        repositoryRevision: intent.repositoryRevision,
        operation: try PLCAccountPreparationOperationFacts(
            signingDIDKey: try XCTUnwrap(regular.verificationMethods["atproto"]),
            rotationDIDKey: try XCTUnwrap(regular.rotationKeys.first),
            signature: regular.signature
        ),
        signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
        rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
        publicGenesisCommitCID: nil,
        stage: .keysStored
    )
    return PreparationSample(did: did, intent: intent, journal: journal)
}

private func validDIDKey() -> String {
    "did:key:zDnaejgmAHMLkBPMBWnkBxyGxpXx8LgE4WJAYDhwZzyoRAddF"
}

private func alternateValidDIDKey() -> String {
    "did:key:zDnaeY3trVxVedZS1deaj8NG4QRMu5yrkGMAmcq4VWMckY7fA"
}

private func validSignature() -> String {
    "9iRdVfzU6ADbVi3zm0V5Qephpl3Dae5odEdDhUBV8aA2TdS1kezQ_9E1YFevVRGE451G_Rdg514dat4ckLGVQg"
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

private func preparationSchemaIsPublicOnly(
    control: SQLiteConnection,
    account: SQLiteConnection
) async throws -> Bool {
    let forbidden = [
        "password", "verifier", "private_key", "access_token",
        "refresh_token", "session", "bearer_token", "signed_operation_json",
    ]
    for (connection, table) in [
        (control, "plc_account_preparation_intents"),
        (account, "plc_account_preparation_journal"),
    ] {
        let rows = try await connection.query("PRAGMA table_info(\(table))")
        let names = rows.compactMap { $0.column("name")?.string?.lowercased() }
        guard !names.isEmpty else { return false }
        if names.contains(where: { name in forbidden.contains(where: name.contains) }) {
            return false
        }
    }
    return true
}

private func preparationValuesArePublicOnly(
    control: SQLiteConnection,
    account: SQLiteConnection
) async throws -> Bool {
    let controlRows = try await control.query(
        """
        SELECT request_id, did, canonical_handle, pds_origin,
               repository_revision, operation_cid
        FROM plc_account_preparation_intents
        """
    )
    let accountRows = try await account.query(
        """
        SELECT request_id, canonical_handle, pds_origin, repository_revision,
               operation_signing_did_key, operation_rotation_did_key,
               operation_signature, signing_key_reference, rotation_key_reference,
               public_genesis_commit_cid
        FROM plc_account_preparation_journal
        """
    )
    let forbidden = [
        "password", "verifier", "private_key", "access_token",
        "refresh_token", "session", "bearer ",
    ]
    let controlColumns = [
        "request_id", "did", "canonical_handle", "pds_origin",
        "repository_revision", "operation_cid",
    ]
    let accountColumns = [
        "request_id", "canonical_handle", "pds_origin", "repository_revision",
        "operation_signing_did_key", "operation_rotation_did_key",
        "operation_signature", "signing_key_reference", "rotation_key_reference",
        "public_genesis_commit_cid",
    ]
    let values = controlRows.flatMap { row in
        controlColumns.compactMap { row.column($0)?.string }
    } + accountRows.flatMap { row in
        accountColumns.compactMap { row.column($0)?.string }
    }
    return !values.map { $0.lowercased() }.contains { value in
        forbidden.contains(where: value.contains)
    }
}

private func tableExists(
    connection: SQLiteConnection,
    table: String
) async throws -> Bool {
    let rows = try await connection.query(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        [.text(table)]
    )
    return rows.count == 1
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
