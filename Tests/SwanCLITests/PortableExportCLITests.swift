import Foundation
import SwanAccounts
import SwanSQLite
import SwanStorage
import XCTest

final class PortableExportCLITests: XCTestCase {
    func testExportRejectsMissingOperatorAuthorityBeforeCreatingStorageOrOutput() throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPortableExportCLI-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let output = root.appending(path: "archive")

        let process = Process()
        process.executableURL = try XCTUnwrap(executableURL())
        process.arguments = [
            "export",
            "--data-directory", root.appending(path: "data").path,
            "--did", "did:plc:abcdefghijklmnopqrstuvwx",
            "--output-directory", output.path,
            "--operator-secret-file", root.appending(path: "missing-operator").path,
            "--account-kek-file", root.appending(path: "missing-kek").path,
        ]
        process.environment = [:]
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        process.waitUntilExit()

        let outputBytes = stdout.fileHandleForReading.readDataToEndOfFile()
        let errorBytes = stderr.fileHandleForReading.readDataToEndOfFile()
        XCTAssertNotEqual(process.terminationStatus, 0)
        XCTAssertTrue(outputBytes.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: root.appending(path: "data/control.sqlite").path
            )
        )
        let error = String(decoding: errorBytes, as: UTF8.self)
        XCTAssertFalse(error.contains(root.path))
        XCTAssertFalse(error.contains("abcdefghijklmnopqrstuvwx"))
    }

    func testExistingOutputIsRejectedBeforeKeyStoreOrDatabaseMutation() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        let control = try await SQLiteControlDatabase(dataDirectory: data)
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: did,
                canonicalHandle: "alice.example.com",
                passwordVerifier: testVerifier,
                signingKey: try AccountControlKeyReference(
                    purpose: .signing,
                    generation: 1
                ),
                rotationKey: try AccountControlKeyReference(
                    purpose: .rotation,
                    generation: 1
                ),
                publicGenesisCommitCID:
                    "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
        )
        try await control.close()
        let account = try await SQLiteAccountDatabase(dataDirectory: data, did: did)
        try await account.close()

        let output = root.appending(path: "existing-output")
        try FileManager.default.createDirectory(
            at: output,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let operatorSecret = root.appending(path: "operator-secret")
        let kek = root.appending(path: "account-kek")
        try protectedWrite(Data("operator-secret".utf8), to: operatorSecret)
        let encodedKEK = Data(repeating: 0xA7, count: 32).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        try protectedWrite(Data(encodedKEK.utf8), to: kek)
        let keyDirectory = root.appending(path: "keys")
        let keyConfiguration = try AccountKeyEncryptionConfiguration(
            activeKeyID: "primary",
            activeKey: Data(repeating: 0xA7, count: 32)
        )
        let keyStore = try FileAccountKeyStore(
            root: keyDirectory,
            configuration: keyConfiguration
        )
        try await keyStore.create(
            Data(repeating: 0x5A, count: 32),
            for: try AccountKeyReference(
                accountDID: did,
                purpose: .signing,
                generation: 1
            )
        )
        let sourceBefore = try treeSnapshot(root)

        let result = try runExport(arguments: [
            "--data-directory", data.path,
            "--did", did,
            "--output-directory", output.path,
            "--operator-secret-file", operatorSecret.path,
            "--account-kek-file", kek.path,
            "--account-key-directory", keyDirectory.path,
        ])

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.stdout.isEmpty)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: output.path), [])
        XCTAssertEqual(try treeSnapshot(root), sourceBefore)
    }

    private func runExport(arguments: [String]) throws -> (
        status: Int32,
        stdout: Data,
        stderr: Data
    ) {
        let process = Process()
        process.executableURL = try XCTUnwrap(executableURL())
        process.arguments = ["export"] + arguments
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

    private func protectedWrite(_ data: Data, to url: URL) throws {
        try data.write(to: url)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: url.path
        )
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPortableExportCLI-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }

    private func treeSnapshot(_ root: URL) throws -> [String: Data] {
        let keys: Set<URLResourceKey> = [.isDirectoryKey, .isRegularFileKey]
        let enumerator = try XCTUnwrap(
            FileManager.default.enumerator(
                at: root,
                includingPropertiesForKeys: Array(keys),
                options: [],
                errorHandler: nil
            )
        )
        var result: [String: Data] = [:]
        for case let url as URL in enumerator {
            let relative = String(url.path.dropFirst(root.path.count + 1))
            let values = try url.resourceValues(forKeys: keys)
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            let mode = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
            if values.isDirectory == true {
                result[relative] = Data("directory:\(mode)".utf8)
            } else if values.isRegularFile == true {
                var value = Data("file:\(mode):".utf8)
                value.append(try Data(contentsOf: url))
                result[relative] = value
            }
        }
        return result
    }

    private func executableURL() -> URL? {
        let packageRoot = URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        for candidate in [
            packageRoot.appending(path: ".build/debug/swan"),
            packageRoot.appending(path: ".build-task19/debug/swan"),
        ] where FileManager.default.isExecutableFile(atPath: candidate.path) {
            return candidate
        }
        return nil
    }
}

private let testVerifier =
    "$argon2id$v=19$m=65536,t=3,p=1$bcdefghijklmnopqrstuvw$BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
