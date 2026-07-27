import Foundation
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
