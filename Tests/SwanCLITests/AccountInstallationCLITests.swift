import Foundation
import SwanSQLite
import XCTest

final class AccountInstallationCLITests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let handle = "alice.example.com"
    private let revision = "3jzfcijpj2z2a"

    func testInstallLocalCreatesRecoverablePublicAccountWithoutPrintingSecrets() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let passwordFile = root.appending(path: "password")
        let password = "correct horse 🦢"
        try Data((password + "\n").utf8).write(to: passwordFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: passwordFile.path)

        let environment = [
            "SWAN_OPERATOR_SECRET": "operator-secret",
            "SWAN_ACCOUNT_KEK": base64URLEncoded(Data(repeating: 0xA7, count: 32)),
        ]
        let first = try runInstall(root: root, passwordFile: passwordFile, environment: environment)
        XCTAssertEqual(first["did"] as? String, did)
        XCTAssertEqual(first["canonicalHandle"] as? String, handle)
        XCTAssertEqual(first["status"] as? String, "active")
        XCTAssertEqual(first["publicGenesisRevision"] as? String, revision)
        XCTAssertEqual(first["recovered"] as? Bool, false)
        XCTAssertNotNil(first["publicGenesisCommitCID"] as? String)
        XCTAssertFalse(String(decoding: try JSONSerialization.data(withJSONObject: first), as: UTF8.self).contains(password))
        XCTAssertFalse(String(decoding: try JSONSerialization.data(withJSONObject: first), as: UTF8.self).contains(environment["SWAN_ACCOUNT_KEK"]!))

        let control = try await SQLiteControlDatabase(dataDirectory: root)
        let account = try await control.account(did: did)
        XCTAssertEqual(account?.canonicalHandle, handle)
        XCTAssertEqual(account?.status.rawValue, "active")
        try await control.close()

        let second = try runInstall(root: root, passwordFile: passwordFile, environment: environment)
        XCTAssertEqual(second["recovered"] as? Bool, true)
    }

    private func runInstall(
        root: URL,
        passwordFile: URL,
        environment: [String: String]
    ) throws -> [String: Any] {
        let process = Process()
        process.executableURL = try XCTUnwrap(executableURL())
        process.arguments = [
            "account", "install-local",
            "--data-directory", root.path,
            "--did", did,
            "--handle", handle,
            "--revision", revision,
            "--password-file", passwordFile.path,
        ]
        process.environment = environment
        let standardOutput = Pipe()
        let standardError = Pipe()
        process.standardOutput = standardOutput
        process.standardError = standardError
        try process.run()
        process.waitUntilExit()
        let output = standardOutput.fileHandleForReading.readDataToEndOfFile()
        let errors = standardError.fileHandleForReading.readDataToEndOfFile()
        XCTAssertEqual(
            process.terminationStatus,
            0,
            "install-local failed: \(String(decoding: errors, as: UTF8.self))"
        )
        return try XCTUnwrap(JSONSerialization.jsonObject(with: output) as? [String: Any])
    }

    private func executableURL() -> URL? {
        let packageRoot = URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let executable = packageRoot.appending(path: ".build/debug/swan")
        return FileManager.default.isExecutableFile(atPath: executable.path) ? executable : nil
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanAccountInstallationCLITests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        return root
    }

    private func base64URLEncoded(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
