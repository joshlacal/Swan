import Crypto
import Foundation
import Petrel
@testable import SwanAccountExport
import SwanSQLite
import SwanStorage
import XCTest

final class PLCCredentialContinuityBackupTests: XCTestCase {
    func testC1ToC2RoundTripRejectsHistoricalC1AndPortableArchiveOmitsTrustInventory()
        async throws
    {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { [fixture] in
            try? await fixture.database.close()
            fixture.remove()
        }
        let issuer = plcIssuer(41)
        let c1 = operationCID("continuity-c1")
        let c2 = operationCID("continuity-c2")
        let control = try await SQLiteControlDatabase(
            dataDirectory: fixture.root
        )
        do {
            _ = try await control.advancePLCCredentialKeyContinuity(
                try .init(
                    issuer: issuer,
                    terminalCID: c1,
                    auditCIDs: [c1]
                )
            )
            _ = try await control.advancePLCCredentialKeyContinuity(
                try .init(
                    issuer: issuer,
                    terminalCID: c2,
                    auditCIDs: [c1, c2]
                )
            )
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }

        let backup = fixture.root.appending(path: "continuity-backup")
        _ = try await SwanOperatorAccountBackupExporter(
            database: fixture.database,
            keyReader: fixture.keyStore,
            now: { Date(timeIntervalSince1970: 1_700_000_000) }
        ).backup(
            account: fixture.account,
            credential: fixture.credential,
            using: fixture.backupKey,
            to: backup
        )
        _ = try SwanOperatorAccountBackupVerifier.verifyBackup(
            at: backup,
            using: fixture.backupKey
        )

        let portableRoot = backup.appending(path: "portable")
        for file in try regularFiles(under: portableRoot) {
            let data = try Data(contentsOf: file)
            XCTAssertNil(data.range(of: Data(issuer.utf8)))
            XCTAssertNil(data.range(of: Data(c1.utf8)))
            XCTAssertNil(data.range(of: Data(c2.utf8)))
        }

        let target = fixture.root.appending(path: "continuity-restored")
        _ = try await SwanOperatorAccountRestorer().restore(
            backupAt: backup,
            using: fixture.backupKey,
            accountKEK: try SwanOperatorAccountKEK(
                rawBytes: Data(repeating: 0xD1, count: 32)
            ),
            to: target
        )
        let restored = try await SQLiteControlDatabase(dataDirectory: target)
        do {
            let restoredInventory =
                try await restored.plcCredentialKeyContinuityInventory()
            let expectedCheckpoint =
                try PLCCredentialKeyContinuityCheckpoint(
                    issuer: issuer,
                    terminalCID: c2
                )
            XCTAssertEqual(
                restoredInventory.checkpoints,
                [expectedCheckpoint]
            )
            do {
                _ = try await restored.advancePLCCredentialKeyContinuity(
                    try .init(
                        issuer: issuer,
                        terminalCID: c1,
                        auditCIDs: [c1]
                    )
                )
                XCTFail("restored C2 checkpoint accepted historical C1")
            } catch {
                XCTAssertEqual(
                    error as? PLCCredentialKeyContinuityStoreError,
                    .continuityViolation
                )
            }
            try await restored.close()
        } catch {
            try? await restored.close()
            throw error
        }
    }

    func testProductionBackupFailsClosedWhenCompanionControlDatabaseIsMissing()
        async throws
    {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { [fixture] in
            try? await fixture.database.close()
            fixture.remove()
        }
        let output = fixture.root.appending(path: "missing-control")

        do {
            _ = try await SwanOperatorAccountBackupExporter(
                database: fixture.database,
                keyReader: fixture.keyStore
            ).backup(
                account: fixture.account,
                credential: fixture.credential,
                using: fixture.backupKey,
                to: output
            )
            XCTFail("backup unexpectedly downgraded missing continuity state")
        } catch {
            XCTAssertEqual(
                error as? SwanOperatorAccountBackupError,
                .failed
            )
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
    }

    func testAuthenticatedMissingDuplicateInvalidAndOversizedInventoriesFailClosed()
        async throws
    {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { [fixture] in
            try? await fixture.database.close()
            fixture.remove()
        }
        let checkpoint = try PLCCredentialKeyContinuityCheckpoint(
            issuer: plcIssuer(1),
            terminalCID: operationCID("valid-terminal")
        )
        let source = fixture.root.appending(path: "tamper-source")
        _ = try await fixture.backup(
            to: source,
            continuityInventory: try .init(checkpoints: [checkpoint])
        )

        let mutations: [(String, (inout [String: Any]) throws -> Void)] = [
            ("missing", { $0.removeValue(forKey: "plcCredentialKeyContinuity") }),
            ("duplicate", { object in
                var rows = try XCTUnwrap(
                    object["plcCredentialKeyContinuity"]
                        as? [[String: Any]]
                )
                rows.append(rows[0])
                object["plcCredentialKeyContinuity"] = rows
            }),
            ("invalid-cid", { object in
                var rows = try XCTUnwrap(
                    object["plcCredentialKeyContinuity"]
                        as? [[String: Any]]
                )
                rows[0]["terminalCID"] = "not-a-cid"
                object["plcCredentialKeyContinuity"] = rows
            }),
            ("oversized", { object in
                object["plcCredentialKeyContinuity"] =
                    (0 ... PLCCredentialKeyContinuityInventory
                        .maximumCheckpointCount).map {
                            [
                                "issuer": self.plcIssuer($0),
                                "terminalCID": self.operationCID(
                                    "oversized-\($0)"
                                ),
                            ]
                        }
            }),
        ]

        for (name, mutation) in mutations {
            let candidate = fixture.root.appending(path: "tampered-\(name)")
            try FileManager.default.copyItem(at: source, to: candidate)
            try rewriteAuthenticatedPayload(
                in: candidate,
                key: fixture.backupKey,
                mutation
            )
            XCTAssertThrowsError(
                try SwanOperatorAccountBackupVerifier.verifyBackup(
                    at: candidate,
                    using: fixture.backupKey
                ),
                name
            ) {
                XCTAssertEqual(
                    $0 as? SwanOperatorAccountBackupError,
                    .failed,
                    name
                )
            }
            await assertRestoreError(
                backup: candidate,
                key: fixture.backupKey,
                target: fixture.root.appending(path: "restore-\(name)"),
                expected: .failed,
                message: name
            )
        }
    }

    func testAuthenticatedLegacyInnerPayloadReportsUnsupportedVersion() async throws {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { [fixture] in
            try? await fixture.database.close()
            fixture.remove()
        }
        let backup = try await fixture.completedBackup(named: "legacy-inner")
        try rewriteAuthenticatedPayload(
            in: backup,
            key: fixture.backupKey
        ) { object in
            object["format"] = "swan-operator-account-secrets-v1"
            object.removeValue(forKey: "plcCredentialKeyContinuity")
        }

        XCTAssertThrowsError(
            try SwanOperatorAccountBackupVerifier.verifyBackup(
                at: backup,
                using: fixture.backupKey
            )
        ) {
            XCTAssertEqual(
                $0 as? SwanOperatorAccountBackupError,
                .unsupportedVersion
            )
        }
        await assertRestoreError(
            backup: backup,
            key: fixture.backupKey,
            target: fixture.root.appending(path: "legacy-restore"),
            expected: .unsupportedVersion,
            message: "legacy authenticated payload"
        )
    }

    private func assertRestoreError(
        backup: URL,
        key: SwanOperatorBackupKey,
        target: URL,
        expected: SwanOperatorAccountRestoreError,
        message: String
    ) async {
        do {
            _ = try await SwanOperatorAccountRestorer().restore(
                backupAt: backup,
                using: key,
                accountKEK: try SwanOperatorAccountKEK(
                    rawBytes: Data(repeating: 0xE2, count: 32)
                ),
                to: target
            )
            XCTFail("expected restore failure: \(message)")
        } catch {
            XCTAssertEqual(
                error as? SwanOperatorAccountRestoreError,
                expected,
                message
            )
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
    }

    private func rewriteAuthenticatedPayload(
        in root: URL,
        key: SwanOperatorBackupKey,
        _ mutate: (inout [String: Any]) throws -> Void
    ) throws {
        let manifestURL = root.appending(path: "manifest.json")
        var manifest = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: Data(contentsOf: manifestURL)
            ) as? [String: Any]
        )
        let portableDigest = try XCTUnwrap(
            manifest["portableManifestSHA256"] as? String
        )
        let profileID = try XCTUnwrap(manifest["profileID"] as? String)
        let envelopeURL = root.appending(path: "operator/secrets.aesgcm")
        let aad = Data(
            [
                "swan-operator-account-backup-v1",
                profileID,
                portableDigest,
            ].joined(separator: "\u{0}").utf8
        )
        let plaintext = try AES.GCM.open(
            AES.GCM.SealedBox(
                combined: Data(contentsOf: envelopeURL)
            ),
            using: SymmetricKey(data: key.bytes),
            authenticating: aad
        )
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: plaintext)
                as? [String: Any]
        )
        try mutate(&object)
        let rewrittenPlaintext = try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let sealed = try AES.GCM.seal(
            rewrittenPlaintext,
            using: SymmetricKey(data: key.bytes),
            authenticating: aad
        )
        let envelope = try XCTUnwrap(sealed.combined)
        try envelope.write(to: envelopeURL)
        manifest["envelopeSHA256"] =
            SwanPortableExportDigest.hex(envelope)
        try JSONSerialization.data(
            withJSONObject: manifest,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ).write(to: manifestURL)
    }

    private func regularFiles(under root: URL) throws -> [URL] {
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }
        return try enumerator.compactMap { element in
            let url = try XCTUnwrap(element as? URL)
            return try url.resourceValues(forKeys: [.isRegularFileKey])
                .isRegularFile == true ? url : nil
        }
    }

    private func plcIssuer(_ index: Int) -> String {
        let alphabet = Array("abcdefghijklmnopqrstuvwxyz234567")
        var value = index
        var suffix = Array(repeating: Character("a"), count: 24)
        for position in suffix.indices.reversed() {
            suffix[position] = alphabet[value & 31]
            value >>= 5
        }
        return "did:plc:\(String(suffix))"
    }

    private func operationCID(_ marker: String) -> String {
        CID.fromDAGCBOR(Data(marker.utf8)).string
    }
}
