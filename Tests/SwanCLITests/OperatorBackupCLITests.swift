import Crypto
import Foundation
import Petrel
import SwanAccountExport
import SwanAccounts
import SwanPublicRepository
import SwanSQLite
import SwanStorage
import XCTest

final class OperatorBackupCLITests: XCTestCase {
    func testBackupAuthorizesBeforeEverySuppliedPathProbe() throws {
        let root = try cliTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let output = root.appending(path: "must-not-exist")
        let sentinel = "operator-backup-path-sentinel"
        let process = try runBackup(
            arguments: [
                "--data-directory", root.appending(path: "\(sentinel)-data").path,
                "--did", "did:plc:abcdefghijklmnopqrstuvwx",
                "--output-directory", output.path,
                "--operator-secret-file", root.appending(path: "missing-operator").path,
                "--account-kek-file", root.appending(path: "\(sentinel)-kek").path,
                "--backup-key-file", root.appending(path: "\(sentinel)-backup").path,
                "--account-key-directory", root.appending(path: "\(sentinel)-keys").path,
            ],
            environment: [:]
        )

        XCTAssertNotEqual(process.status, 0)
        XCTAssertTrue(process.stdout.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), [])
        let error = String(decoding: process.stderr, as: UTF8.self)
        XCTAssertFalse(error.contains(sentinel))
        XCTAssertFalse(error.contains(root.path))
        XCTAssertFalse(error.contains("abcdefghijklmnopqrstuvwx"))
        XCTAssertTrue(error.contains("operator backup failed"))
        XCTAssertFalse(error.contains("operator secret file is unavailable"))
    }

    func testBackupEmitsExactSanitizedSuccessAndProducesVerifiableArchive() async throws {
        let fixture = try await OperatorBackupCLIFixture()
        defer { fixture.remove() }
        let dataBefore = try cliTreeSnapshot(fixture.dataDirectory)
        let keysBefore = try cliTreeSnapshot(fixture.keyDirectory)

        let result = try runBackup(arguments: fixture.arguments, environment: [:])
        XCTAssertEqual(result.status, 0, String(decoding: result.stderr, as: UTF8.self))
        XCTAssertTrue(result.stderr.isEmpty)
        XCTAssertEqual(result.stdout.last, 0x0A)
        let outputJSON = try XCTUnwrap(
            JSONSerialization.jsonObject(with: result.stdout.dropLast()) as? [String: Any]
        )
        XCTAssertEqual(
            Set(outputJSON.keys),
            Set([
                "backupManifestSHA256", "containsEncryptedPrivateKeys", "did",
                "fileCount", "outputDirectory", "portableManifestSHA256",
            ])
        )
        XCTAssertEqual(outputJSON["did"] as? String, fixture.did)
        XCTAssertEqual(outputJSON["outputDirectory"] as? String, fixture.output.path)
        XCTAssertEqual(outputJSON["containsEncryptedPrivateKeys"] as? Bool, true)
        let verification = try SwanOperatorAccountBackupVerifier.verifyBackup(
            at: fixture.output,
            using: SwanOperatorBackupKey(secretFile: fixture.backupKeyFile)
        )
        XCTAssertEqual(
            outputJSON["backupManifestSHA256"] as? String,
            verification.backupManifestSHA256
        )
        XCTAssertEqual(
            outputJSON["portableManifestSHA256"] as? String,
            verification.portableManifestSHA256
        )
        XCTAssertEqual(outputJSON["fileCount"] as? Int, verification.fileCount)

        var exposed = result.stdout + result.stderr
        exposed.append(try cliAllFileBytes(under: fixture.output))
        for sentinel in fixture.secretSentinels {
            XCTAssertNil(exposed.range(of: sentinel))
        }
        XCTAssertEqual(try cliTreeSnapshot(fixture.dataDirectory), dataBefore)
        XCTAssertEqual(try cliTreeSnapshot(fixture.keyDirectory), keysBefore)
    }

    func testBackupFailuresAreOneSafeMessageWithEmptyStdout() async throws {
        let fixture = try await OperatorBackupCLIFixture()
        defer { fixture.remove() }
        let dataBefore = try cliTreeSnapshot(fixture.dataDirectory)
        let keysBefore = try cliTreeSnapshot(fixture.keyDirectory)
        try cliProtectedWrite(Data("not-a-key".utf8), to: fixture.backupKeyFile)

        let result = try runBackup(arguments: fixture.arguments, environment: [:])
        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.stdout.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.output.path))
        let error = String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(error.contains("operator backup failed"))
        XCTAssertFalse(error.contains(fixture.root.path))
        XCTAssertFalse(error.contains(fixture.did))
        for sentinel in fixture.secretSentinels {
            XCTAssertNil(result.stderr.range(of: sentinel))
        }
        XCTAssertEqual(try cliTreeSnapshot(fixture.dataDirectory), dataBefore)
        XCTAssertEqual(try cliTreeSnapshot(fixture.keyDirectory), keysBefore)
    }

    func testBackupKeyHasNoEnvironmentOrLiteralOptionFallback() async throws {
        let fixture = try await OperatorBackupCLIFixture()
        defer { fixture.remove() }
        var arguments = fixture.arguments
        let optionIndex = try XCTUnwrap(arguments.firstIndex(of: "--backup-key-file"))
        arguments.removeSubrange(optionIndex ... optionIndex + 1)

        let result = try runBackup(
            arguments: arguments,
            environment: [
                "SWAN_OPERATOR_BACKUP_KEY":
                    Data(repeating: 0xC3, count: 32).cliBase64URL,
            ]
        )
        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.stdout.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.output.path))
    }

    func testBackupRejectsNoncanonicalMountedAccountKEK() async throws {
        let fixture = try await OperatorBackupCLIFixture()
        defer { fixture.remove() }
        try cliProtectedWrite(
            Data(Data(repeating: 0xA7, count: 32).base64EncodedString().utf8),
            to: fixture.accountKEKFile
        )

        let result = try runBackup(arguments: fixture.arguments, environment: [:])
        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.stdout.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.output.path))
        XCTAssertTrue(
            String(decoding: result.stderr, as: UTF8.self)
                .contains("operator backup failed")
        )
    }

    private func runBackup(
        arguments: [String],
        environment: [String: String]
    ) throws -> (status: Int32, stdout: Data, stderr: Data) {
        let process = Process()
        process.executableURL = try XCTUnwrap(cliExecutableURL())
        process.arguments = ["backup"] + arguments
        process.environment = environment
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        process.waitUntilExit()
        return (
            process.terminationStatus,
            stdout.fileHandleForReading.readDataToEndOfFile(),
            stderr.fileHandleForReading.readDataToEndOfFile()
        )
    }
}

final class OperatorAccountRestoreCLITests: XCTestCase {
    func testEncryptedBackupModeRestoresAbsentDataRootWithExactSortedJSON() async throws {
        let fixture = try await OperatorBackupCLIFixture()
        defer { fixture.remove() }
        let backup = try runCLI(command: "backup", arguments: fixture.arguments)
        XCTAssertEqual(backup.status, 0, String(decoding: backup.stderr, as: UTF8.self))

        let target = fixture.root.appending(path: "restored-data")
        let restored = try runCLI(command: "restore", arguments: [
            "--data-directory", target.path,
            "--input-directory", fixture.output.path,
            "--operator-secret-file", fixture.operatorSecretFile.path,
            "--backup-key-file", fixture.backupKeyFile.path,
            "--account-kek-file", fixture.accountKEKFile.path,
            "--account-kek-id", "primary",
        ])

        XCTAssertEqual(
            restored.status,
            0,
            String(decoding: restored.stderr, as: UTF8.self)
        )
        XCTAssertTrue(restored.stderr.isEmpty)
        let decoded = try JSONDecoder().decode(
            SwanOperatorAccountRestoreResult.self,
            from: restored.stdout
        )
        XCTAssertEqual(decoded.status, "restored")
        XCTAssertEqual(decoded.did, fixture.did)
        XCTAssertEqual(decoded.targetDataDirectory, target.path)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        XCTAssertEqual(restored.stdout, try encoder.encode(decoded) + Data("\n".utf8))
        for sentinel in fixture.secretSentinels {
            XCTAssertNil(restored.stdout.range(of: sentinel))
            XCTAssertNil(restored.stderr.range(of: sentinel))
        }

        let control = try await SQLiteControlDatabase(dataDirectory: target)
        let activeDIDs = try await control.activeAccountDIDs()
        XCTAssertEqual(activeDIDs, [fixture.did])
        try await control.close()
    }

    func testEncryptedBackupModeFailureIsOneSafeMessageAndLeavesNoTarget() async throws {
        let fixture = try await OperatorBackupCLIFixture()
        defer { fixture.remove() }
        let backup = try runCLI(command: "backup", arguments: fixture.arguments)
        XCTAssertEqual(backup.status, 0)
        let wrongKey = fixture.root.appending(path: "wrong-backup-key")
        try cliProtectedWrite(
            Data(Data(repeating: 0x91, count: 32).cliBase64URL.utf8),
            to: wrongKey
        )
        let target = fixture.root.appending(path: "failed-restored-data")

        let restored = try runCLI(command: "restore", arguments: [
            "--data-directory", target.path,
            "--input-directory", fixture.output.path,
            "--operator-secret-file", fixture.operatorSecretFile.path,
            "--backup-key-file", wrongKey.path,
            "--account-kek-file", fixture.accountKEKFile.path,
        ])

        XCTAssertNotEqual(restored.status, 0)
        XCTAssertTrue(restored.stdout.isEmpty)
        let diagnostic = String(decoding: restored.stderr, as: UTF8.self)
        XCTAssertTrue(diagnostic.contains("operator backup restore failed"))
        XCTAssertFalse(diagnostic.contains(fixture.root.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
        for sentinel in fixture.secretSentinels {
            XCTAssertNil(restored.stderr.range(of: sentinel))
        }
    }

    private func runCLI(
        command: String,
        arguments: [String]
    ) throws -> (status: Int32, stdout: Data, stderr: Data) {
        let process = Process()
        process.executableURL = try XCTUnwrap(cliExecutableURL())
        process.arguments = [command] + arguments
        process.environment = [:]
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        process.waitUntilExit()
        return (
            process.terminationStatus,
            stdout.fileHandleForReading.readDataToEndOfFile(),
            stderr.fileHandleForReading.readDataToEndOfFile()
        )
    }
}

private struct OperatorBackupCLIFixture {
    let root: URL
    let dataDirectory: URL
    let output: URL
    let operatorSecretFile: URL
    let accountKEKFile: URL
    let backupKeyFile: URL
    let keyDirectory: URL
    let did: String
    let secretSentinels: [Data]
    let readOnlyControl: SQLiteControlDatabase
    let readOnlyAccount: SQLiteAccountDatabase

    init() async throws {
        root = try cliTemporaryDirectory()
        dataDirectory = root.appending(path: "data")
        output = root.appending(path: "operator-backup")
        operatorSecretFile = root.appending(path: "operator-secret")
        accountKEKFile = root.appending(path: "account-kek")
        backupKeyFile = root.appending(path: "backup-key")
        keyDirectory = root.appending(path: "keys")

        let operatorSecret = Data("operator-secret-backup-cli-sentinel".utf8)
        let kek = Data(repeating: 0xA7, count: 32)
        let backupKey = Data(repeating: 0xC3, count: 32)
        try cliProtectedWrite(operatorSecret, to: operatorSecretFile)
        try cliProtectedWrite(Data(kek.cliBase64URL.utf8), to: accountKEKFile)
        try cliProtectedWrite(Data(backupKey.cliBase64URL.utf8), to: backupKeyFile)

        let signing = P256.Signing.PrivateKey()
        let rotation = P256.Signing.PrivateKey()
        let handle = "alice.example.com"
        let unsigned = try PLCATProfile.regularOperation(
            handle: handle,
            signingPublicKey: signing.publicKey,
            rotationPublicKeys: [rotation.publicKey],
            pdsOrigin: URL(string: "https://pds.example.com")!,
            prev: nil
        )
        let operation = try PLCOperationCodec.sign(.regular(unsigned), using: rotation)
        did = try PLCOperationCodec.genesisDID(for: operation)
        let signingReference = try AccountControlKeyReference(
            purpose: .signing,
            generation: 1
        )
        let rotationReference = try AccountControlKeyReference(
            purpose: .rotation,
            generation: 1
        )

        let keys = try FileAccountKeyStore(
            root: keyDirectory,
            configuration: AccountKeyEncryptionConfiguration(
                activeKeyID: "primary",
                activeKey: kek
            )
        )
        try await keys.createBatch([
            try AccountKeyMaterial(
                reference: AccountKeyReference(
                    accountDID: did,
                    purpose: .signing,
                    generation: 1
                ),
                key: signing.rawRepresentation
            ),
            try AccountKeyMaterial(
                reference: AccountKeyReference(
                    accountDID: did,
                    purpose: .rotation,
                    generation: 1
                ),
                key: rotation.rawRepresentation
            ),
        ])
        let accountDatabase = try await SQLiteAccountDatabase(
            dataDirectory: dataDirectory,
            did: did
        )
        let genesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: "3jzfcijpj2z2a",
            signingKey: signing
        )
        _ = try await accountDatabase.installPublicRepositoryGenesis(
            genesis,
            signingPublicKey: signing.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let journal = try PLCAccountPreparationJournal(
            requestID: "operator-backup-cli-test",
            canonicalHandle: handle,
            pdsOrigin: "https://pds.example.com",
            repositoryRevision: genesis.revision,
            operation: PLCAccountPreparationOperationFacts(
                signingDIDKey: XCTUnwrap(operation.regular?.verificationMethods["atproto"]),
                rotationDIDKey: XCTUnwrap(operation.regular?.rotationKeys.first),
                signature: XCTUnwrap(operation.regular?.signature)
            ),
            signingKey: signingReference,
            rotationKey: rotationReference,
            publicGenesisCommitCID: nil,
            stage: .keysStored
        )
        _ = try await accountDatabase.installPLCAccountPreparationJournal(journal)
        _ = try await accountDatabase.advancePLCAccountPreparationJournal(
            requestID: journal.requestID,
            expectedStage: .keysStored,
            to: .repositoryInstalled,
            publicGenesisCommitCID: genesis.commitCID.string
        )
        _ = try await accountDatabase.advancePLCAccountPreparationJournal(
            requestID: journal.requestID,
            expectedStage: .repositoryInstalled,
            to: .submissionPending,
            publicGenesisCommitCID: nil
        )
        _ = try await accountDatabase.advancePLCAccountPreparationJournal(
            requestID: journal.requestID,
            expectedStage: .submissionPending,
            to: .submitted,
            publicGenesisCommitCID: nil
        )
        try await accountDatabase.close()

        let control = try await SQLiteControlDatabase(dataDirectory: dataDirectory)
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: did,
                canonicalHandle: handle,
                passwordVerifier: operatorBackupCLIVerifier,
                signingKey: signingReference,
                rotationKey: rotationReference,
                publicGenesisCommitCID: genesis.commitCID.string,
                createdAt: Date(timeIntervalSince1970: 1_700_000_000)
            )
        )
        try await control.close()
        // Establish SQLite's read-only WAL/SHM sidecars before the immutable
        // source snapshot. The backup must not alter their durable bytes.
        readOnlyControl = try await SQLiteControlDatabase(
            dataDirectory: dataDirectory,
            openMode: .existingPortableExportSource
        )
        readOnlyAccount = try await SQLiteAccountDatabase(
            dataDirectory: dataDirectory,
            did: did,
            openMode: .existingPortableExportSource
        )
        _ = try await readOnlyControl.account(did: did)
        _ = try await readOnlyAccount.portableExportInventory()
        secretSentinels = [
            operatorSecret,
            kek,
            backupKey,
            signing.rawRepresentation,
            rotation.rawRepresentation,
            Data(operatorBackupCLIVerifier.utf8),
        ]
    }

    var arguments: [String] {
        [
            "--data-directory", dataDirectory.path,
            "--did", did,
            "--output-directory", output.path,
            "--operator-secret-file", operatorSecretFile.path,
            "--account-kek-file", accountKEKFile.path,
            "--backup-key-file", backupKeyFile.path,
            "--account-kek-id", "primary",
            "--account-key-directory", keyDirectory.path,
        ]
    }

    func remove() {
        Task {
            try? await readOnlyAccount.close()
            try? await readOnlyControl.close()
        }
        try? FileManager.default.removeItem(at: root)
    }
}

private func cliTemporaryDirectory() throws -> URL {
    let root = FileManager.default.temporaryDirectory
        .appending(path: "SwanOperatorBackupCLI-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
        at: root,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    return root
}

private func cliProtectedWrite(_ data: Data, to url: URL) throws {
    try data.write(to: url)
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o600],
        ofItemAtPath: url.path
    )
}

private func cliAllFileBytes(under root: URL) throws -> Data {
    let enumerator = try XCTUnwrap(
        FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [],
            errorHandler: nil
        )
    )
    var data = Data()
    for case let url as URL in enumerator
    where try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true {
        data.append(try Data(contentsOf: url))
    }
    return data
}

private func cliTreeSnapshot(_ root: URL) throws -> [String: Data] {
    let canonicalRoot = root.resolvingSymlinksInPath().path
    let enumerator = try XCTUnwrap(
        FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey],
            options: [],
            errorHandler: nil
        )
    )
    var snapshot: [String: Data] = [:]
    for case let url as URL in enumerator {
        let canonicalPath = url.resolvingSymlinksInPath().path
        let relative = String(canonicalPath.dropFirst(canonicalRoot.count + 1))
        let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey])
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        let mode = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        if values.isDirectory == true {
            snapshot[relative] = Data("directory:\(mode)".utf8)
        } else if values.isRegularFile == true {
            var value = Data("file:\(mode):".utf8)
            if url.lastPathComponent.hasSuffix(".sqlite-shm") {
                let size = (attributes[.size] as? NSNumber)?.uint64Value ?? 0
                value.append(Data("shared-memory:\(size)".utf8))
            } else {
                value.append(try Data(contentsOf: url))
            }
            snapshot[relative] = value
        }
    }
    return snapshot
}

private func cliExecutableURL() -> URL? {
    if let override = ProcessInfo.processInfo.environment["SWAN_TEST_EXECUTABLE"],
       !override.isEmpty,
       FileManager.default.isExecutableFile(atPath: override) {
        return URL(filePath: override)
    }
    let packageRoot = URL(filePath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    for candidate in [
        packageRoot.appending(path: ".build/debug/swan"),
        packageRoot.appending(path: ".build-task21/debug/swan"),
    ] where FileManager.default.isExecutableFile(atPath: candidate.path) {
        return candidate
    }
    return nil
}

private extension Data {
    var cliBase64URL: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private let operatorBackupCLIVerifier =
    "$argon2id$v=19$m=65536,t=3,p=1$bcdefghijklmnopqrstuvw$BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
