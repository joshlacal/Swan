import Foundation
import SwanSQLite
import SwanStorage
import XCTest

final class ForumLabCLITests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"

    func testForumHelpListsSubcommands() throws {
        let result = try runCLI(command: ["forum", "--help"])
        XCTAssertEqual(result.status, 0, String(decoding: result.stderr, as: UTF8.self))
        let output = String(decoding: result.stdout, as: UTF8.self)
        XCTAssertTrue(output.contains("provision"), output)
        XCTAssertTrue(output.contains("post"), output)
        XCTAssertTrue(output.contains("thread"), output)
    }

    func testForumProvisionRejectsMissingOAuthEnvironment() throws {
        let result = try runCLI(
            command: [
                "forum", "provision",
                "--authority-url", "https://127.0.0.1:1",
                "--space", spaceURI,
                "--member-did", did,
                "--authority-auth", "oauth",
                "--request-timeout-seconds", "0.2",
            ],
            environment: [
                "SWAN_LAB_AUTHORITY_HANDLE": "",
                "SWAN_LAB_AUTHORITY_PASSWORD": "",
            ]
        )
        XCTAssertNotEqual(result.status, 0)
        let output = String(decoding: result.stdout, as: UTF8.self)
        let errors = String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(
            (output + errors).contains("environment variable is unavailable"),
            output + errors
        )
    }

    func testForumPostFailureWritesSanitizedArtifact() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let output = directory.appending(path: "post.json")

        let result = try runCLI(
            command: [
                "forum", "post",
                "--producer-url", "https://127.0.0.1:1",
                "--space", spaceURI,
                "--text", "private fixture text",
                "--repo", did,
                "--producer-auth", "bearer",
                "--request-timeout-seconds", "0.2",
                "--output", output.path,
                "--no-fail-on-failure",
            ],
            environment: ["SWAN_LAB_PRODUCER_TOKEN": "test-token"]
        )
        XCTAssertEqual(result.status, 0, String(decoding: result.stderr, as: UTF8.self))
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: output)) as? [String: Any]
        )
        XCTAssertEqual(object["status"] as? String, "failed")
        XCTAssertEqual(object["repositoryDID"] as? String, did)
        XCTAssertNil(object["uri"])
        XCTAssertNil(object["cid"])
        XCTAssertNotNil(object["errorCode"] as? String)
        let serialized = String(decoding: try Data(contentsOf: output), as: UTF8.self)
        XCTAssertFalse(serialized.contains("test-token"))
        XCTAssertFalse(serialized.contains("access_token"))
        XCTAssertFalse(serialized.contains("dpop"))
    }

    func testForumPostValidationFailureDoesNotWriteArtifact() throws {
        let result = try runCLI(
            command: [
                "forum", "post",
                "--space", "not-a-space-uri",
                "--text", "hello",
            ]
        )
        XCTAssertNotEqual(result.status, 0)
        let output = String(decoding: result.stdout, as: UTF8.self)
        let errors = String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(
            (output + errors).contains("not a valid space URI"),
            output + errors
        )
    }

    func testForumThreadFailureWritesSanitizedArtifact() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        try FileManager.default.createDirectory(
            at: data,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let control = try await SQLiteControlDatabase(dataDirectory: data)
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: did,
                canonicalHandle: "carol.example.com",
                passwordVerifier: "$argon2id$v=19$m=65536,t=3,p=1$bcdefghijklmnopqrstuvw$BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
                signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
                rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1)
            )
        )
        try await control.close()
        // Materialize the account directory and database file so the CLI's
        // existingManaged open can find them (mirrors account onboarding).
        let materialized = try await SQLiteAccountDatabase(dataDirectory: data, did: did)
        try await materialized.close()
        let output = root.appending(path: "thread.json")

        let result = try runCLI(
            command: [
                "forum", "thread",
                "--consumer-url", "https://127.0.0.1:1",
                "--authority-url", "https://127.0.0.1:1",
                "--space", spaceURI,
                "--receiver-did", did,
                "--data-directory", data.path,
                "--consumer-auth", "bearer",
                "--request-timeout-seconds", "0.2",
                "--output", output.path,
                "--no-fail-on-failure",
            ],
            environment: [
                "SWAN_LAB_CONSUMER_TOKEN": "test-consumer-token",
                "SWAN_LAB_PERMISSIONED_COMMIT_KEY": secp256k1Key,
            ]
        )
        XCTAssertEqual(result.status, 0, String(decoding: result.stderr, as: UTF8.self))
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: output)) as? [String: Any]
        )
        XCTAssertEqual(object["status"] as? String, "failed")
        XCTAssertEqual(object["space"] as? String, spaceURI)
        XCTAssertEqual((object["writers"] as? [Any])?.isEmpty, true)
        XCTAssertEqual((object["thread"] as? [Any])?.isEmpty, true)
        XCTAssertNotNil(object["errorCode"] as? String)
        let serialized = String(decoding: try Data(contentsOf: output), as: UTF8.self)
        XCTAssertFalse(serialized.contains("test-consumer-token"))
        XCTAssertFalse(serialized.contains("access_token"))
        XCTAssertFalse(serialized.contains("eyJ"))
    }

    func testForumThreadRejectsUnmanagedReceiver() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let result = try runCLI(
            command: [
                "forum", "thread",
                "--consumer-url", "https://127.0.0.1:1",
                "--authority-url", "https://127.0.0.1:1",
                "--space", spaceURI,
                "--receiver-did", did,
                "--data-directory", root.path,
                "--consumer-auth", "bearer",
                "--request-timeout-seconds", "0.2",
                "--no-fail-on-failure",
            ],
            environment: ["SWAN_LAB_PERMISSIONED_COMMIT_KEY": secp256k1Key]
        )
        XCTAssertNotEqual(result.status, 0)
        let output = String(decoding: result.stdout, as: UTF8.self)
        let errors = String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(
            (output + errors).contains("receiver account is not managed"),
            output + errors
        )
    }

    func testForumThreadRejectsMalformedWriterHostBeforeNetwork() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        for malformed in ["garbage", "did:plc:abcdefghijklmnopqrstuvwx=not-a-url"] {
            let result = try runCLI(
                command: [
                    "forum", "thread",
                    "--consumer-url", "https://127.0.0.1:1",
                    "--authority-url", "https://127.0.0.1:1",
                    "--space", spaceURI,
                    "--receiver-did", did,
                    "--data-directory", root.path,
                    "--consumer-auth", "bearer",
                    "--request-timeout-seconds", "0.2",
                    "--writer-host", malformed,
                    "--no-fail-on-failure",
                ],
                environment: ["SWAN_LAB_PERMISSIONED_COMMIT_KEY": secp256k1Key]
            )
            XCTAssertNotEqual(result.status, 0)
            let output = String(decoding: result.stdout, as: UTF8.self)
            let errors = String(decoding: result.stderr, as: UTF8.self)
            XCTAssertTrue(
                (output + errors).contains("writer-host"),
                output + errors
            )
        }
    }

    func testForumThreadAcceptsWriterHostWithPerWriterCommitKey() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let data = root.appending(path: "data")
        try FileManager.default.createDirectory(
            at: data,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let control = try await SQLiteControlDatabase(dataDirectory: data)
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: did,
                canonicalHandle: "carol.example.com",
                passwordVerifier: "$argon2id$v=19$m=65536,t=3,p=1$bcdefghijklmnopqrstuvw$BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
                signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
                rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1)
            )
        )
        try await control.close()
        let materialized = try await SQLiteAccountDatabase(dataDirectory: data, did: did)
        try await materialized.close()
        let output = root.appending(path: "thread.json")

        let result = try runCLI(
            command: [
                "forum", "thread",
                "--consumer-url", "https://127.0.0.1:1",
                "--authority-url", "https://127.0.0.1:1",
                "--space", spaceURI,
                "--receiver-did", did,
                "--data-directory", data.path,
                "--consumer-auth", "bearer",
                "--request-timeout-seconds", "0.2",
                "--writer-host", "\(did)=https://127.0.0.1:2:did:key:zQ3shqwJEJyMBsBXCWyCBpUBMqxcon9oHB7mCvx4sSpMdLJwc",
                "--output", output.path,
                "--no-fail-on-failure",
            ],
            environment: ["SWAN_LAB_CONSUMER_TOKEN": "test-consumer-token"]
        )
        XCTAssertEqual(result.status, 0, String(decoding: result.stderr, as: UTF8.self))
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: output)) as? [String: Any]
        )
        XCTAssertEqual(object["status"] as? String, "failed")
        XCTAssertNotNil(object["errorCode"] as? String)
        let serialized = String(decoding: try Data(contentsOf: output), as: UTF8.self)
        XCTAssertFalse(serialized.contains("test-consumer-token"))
        XCTAssertFalse(serialized.contains("did:key:zQ3shqw"))
    }

    private var spaceURI: String {
        "at://\(did)/space/blue.catbird.lab.forum/lab-1"
    }

    private var secp256k1Key: String {
        Data([0x02] + Data(repeating: 0x01, count: 32)).base64URLEncodedString()
    }

    private func runCLI(
        command: [String],
        environment: [String: String] = [:]
    ) throws -> (status: Int32, stdout: Data, stderr: Data) {
        let process = Process()
        process.executableURL = try XCTUnwrap(executableURL())
        process.arguments = ["lab"] + command
        var processEnvironment = ProcessInfo.processInfo.environment
        for (key, value) in environment {
            if value.isEmpty {
                processEnvironment.removeValue(forKey: key)
            } else {
                processEnvironment[key] = value
            }
        }
        process.environment = processEnvironment
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

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "ForumLabCLI-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }

    private func executableURL() throws -> URL {
        if let override = ProcessInfo.processInfo.environment[
            "SWAN_TEST_EXECUTABLE"
        ], !override.isEmpty {
            let executable = URL(fileURLWithPath: override)
            guard FileManager.default.isExecutableFile(
                atPath: executable.path
            ) else {
                throw XCTSkip("SWAN_TEST_EXECUTABLE is not executable")
            }
            return executable
        }
        let coBuiltExecutable = Bundle(for: ForumLabCLITests.self)
            .bundleURL
            .deletingLastPathComponent()
            .appending(path: "swan")
        if FileManager.default.isExecutableFile(
            atPath: coBuiltExecutable.path
        ) {
            return coBuiltExecutable
        }
        throw XCTSkip(
            "co-built swan executable is unavailable; set SWAN_TEST_EXECUTABLE explicitly"
        )
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
