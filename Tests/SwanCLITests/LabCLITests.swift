import Foundation
import XCTest

final class LabCLITests: XCTestCase {
    func testLabValidateRunsFromRepoRoot() throws {
        let root = repoRoot()
        let result = try runCLI(command: ["validate", "--root", root.path])
        let output = String(decoding: result.stdout, as: UTF8.self)
        let errors = String(decoding: result.stderr, as: UTF8.self)
        if output.contains("LAB PREREQUISITES OK") && output.contains("3f6c96d5d2d25438bd40fa89d6ecc37865f8e354") {
            return
        }
        if errors.contains("missingReferenceArchive") {
            throw XCTSkip("reference cache not fetched in this environment")
        }
        XCTAssertEqual(result.status, 0, errors)
        XCTAssertTrue(output.contains("LAB PREREQUISITES OK"))
        XCTAssertTrue(output.contains("3f6c96d5d2d25438bd40fa89d6ecc37865f8e354"))
    }

    func testLabScenarioCommandWritesSanitizedFixture() throws {
        let outputFile = try temporaryDirectory().appending(path: "scenario-artifact.json")
        defer { try? FileManager.default.removeItem(at: outputFile) }

        let result = try runCLI(
            command: [
                "scenario",
                "--name", "scenario-smoke",
                "--fault", "offline",
                "--output", outputFile.path,
                "--swan-base-url", "https://127.0.0.1:1",
                "--reference-base-url", "https://127.0.0.1:1",
                "--request-timeout-seconds", "0.2",
                "--no-fail-on-failure",
            ]
        )
        XCTAssertEqual(result.status, 0, String(decoding: result.stderr, as: UTF8.self))
        XCTAssertTrue(FileManager.default.fileExists(atPath: outputFile.path))

        let decoded = try JSONSerialization.jsonObject(with: Data(contentsOf: outputFile), options: [])
        guard let artifact = decoded as? [String: Any] else {
            return XCTFail("artifact is not a dictionary")
        }

        XCTAssertEqual(artifact["scenario"] as? String, "scenario-smoke")
        XCTAssertEqual(artifact["status"] as? String, "passed")
        XCTAssertEqual(artifact["faultModes"] as? [String], ["offline"])
        XCTAssertNotNil(artifact["hostResults"])
        XCTAssertNotNil(artifact["startedAt"])
        if let convergence = artifact["convergence"] as? [[String: Any]] {
            XCTAssertFalse(convergence.isEmpty)
        } else {
            XCTFail("missing or invalid convergence field")
        }

        if let hostResults = artifact["hostResults"] as? [[String: Any]] {
            for host in hostResults {
                let hostBaseURL = try XCTUnwrap(host["baseURL"] as? String)
                XCTAssertTrue(
                    hostBaseURL.hasPrefix("https://127.0.0.1:1"),
                    "expected base URL to be for 127.0.0.1:1, got \(hostBaseURL)"
                )
                guard let endpointResults = host["endpointResults"] as? [[String: Any]] else {
                    return XCTFail("host entry missing endpointResults")
                }
                XCTAssertFalse(endpointResults.isEmpty)
                for endpoint in endpointResults {
                    XCTAssertNil(endpoint["expectedError"] as? String)
                    if let requestSummary = endpoint["requestSummary"] as? [String: Any] {
                        let raw = requestSummary.map { "\($0.key)=\($0.value)" }.joined(separator: " ")
                        XCTAssertFalse(raw.contains("password"))
                    }
                }
            }
        } else {
            XCTFail("missing hostResults")
        }
    }

    func testLabSemanticCommandWritesDurableSummaryArtifact() throws {
        let outputFile = try temporaryDirectory().appending(path: "semantic-artifact.json")
        defer { try? FileManager.default.removeItem(at: outputFile) }

        let result = try runCLI(
            command: [
                "semantic",
                "--name", "cli-semantic-smoke",
                "--output", outputFile.path,
            ]
        )
        XCTAssertEqual(result.status, 0, String(decoding: result.stderr, as: UTF8.self))
        XCTAssertTrue(FileManager.default.fileExists(atPath: outputFile.path))

        let decoded = try JSONSerialization.jsonObject(
            with: Data(contentsOf: outputFile),
            options: []
        )
        guard let artifact = decoded as? [String: Any] else {
            return XCTFail("artifact is not a dictionary")
        }
        XCTAssertEqual(artifact["scenario"] as? String, "cli-semantic-smoke")
        XCTAssertEqual(artifact["implementation"] as? String, "swan-durable-to-swan-durable")
        XCTAssertEqual(artifact["status"] as? String, "passed")
        XCTAssertEqual(artifact["operationCount"] as? Int, 4)
        XCTAssertEqual(artifact["recordCount"] as? Int, 1)
        XCTAssertEqual((artifact["checks"] as? [[String: Any]])?.count, 18)
        XCTAssertNotNil(artifact["carDigest"] as? String)
        XCTAssertNil(artifact["errorCode"] as? String)
        let serialized = String(decoding: try Data(contentsOf: outputFile), as: UTF8.self).lowercased()
        for forbidden in ["access_token", "refresh_token", "private_key", "record_value"] {
            XCTAssertFalse(serialized.contains(forbidden), "artifact leaked forbidden key: (forbidden)")
        }
    }

    func testLabStatefulFaultMatrixValidatesAndSanitizesWitnesses() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let input = directory.appending(path: "witnesses.json")
        let output = directory.appending(path: "matrix.json")
        let before: [String: Any] = [
            "generation": 1,
            "revision": "222222222222a",
            "commitment": String(repeating: "a", count: 64),
        ]
        let intended: [String: Any] = [
            "generation": 1,
            "revision": "222222222222b",
            "commitment": String(repeating: "b", count: 64),
        ]
        let failureModes = Set(["offline", "disconnected", "reordered", "corrupted"])
        let rejectingModes = Set(["duplicated", "reordered", "corrupted"])
        let cells = [
            "normal", "offline", "disconnected", "delayed",
            "duplicated", "reordered", "corrupted",
        ].map { mode -> [String: Any] in
            [
                "mode": mode,
                "before": before,
                "intended": intended,
                "afterFault": failureModes.contains(mode) ? before : intended,
                "afterHeal": intended,
                "faultObserved": mode != "normal",
                "invalidDeliveryRejected": rejectingModes.contains(mode),
            ]
        }
        try JSONSerialization.data(
            withJSONObject: ["scenario": "cli-stateful-fault", "cells": cells],
            options: [.sortedKeys]
        ).write(to: input, options: .atomic)

        let result = try runCLI(command: [
            "stateful-fault-matrix",
            "--input", input.path,
            "--output", output.path,
        ])
        XCTAssertEqual(result.status, 0, String(decoding: result.stderr, as: UTF8.self))
        let artifact = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(contentsOf: output))
                as? [String: Any]
        )
        XCTAssertEqual(artifact["status"] as? String, "passed")
        XCTAssertEqual(artifact["kind"] as? String, "stateful-cross-host-fault-matrix")
        XCTAssertEqual((artifact["cells"] as? [[String: Any]])?.count, 7)
        let permissions = try FileManager.default.attributesOfItem(
            atPath: output.path
        )[.posixPermissions] as? NSNumber
        XCTAssertEqual(permissions?.intValue, 0o600)
    }

    func testLabStatefulFaultMatrixFailsClosedOnInvalidWitness() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let input = directory.appending(path: "invalid.json")
        try Data(#"{"scenario":"invalid","cells":[]}"#.utf8).write(
            to: input,
            options: .atomic
        )
        let result = try runCLI(command: [
            "stateful-fault-matrix",
            "--input", input.path,
            "--output", directory.appending(path: "matrix.json").path,
        ])
        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(
            (String(decoding: result.stdout, as: UTF8.self)
                + String(decoding: result.stderr, as: UTF8.self))
                .contains("stateful fault matrix did not pass")
        )
    }

    func testLabMatrixCommandWritesOneArtifactPerMode() throws {
        let outputDirectory = try temporaryDirectory().appending(path: "artifacts")
        try FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: outputDirectory) }

        let result = try runCLI(
            command: [
                "matrix",
                "--name", "matrix-smoke",
                "--output-directory", outputDirectory.path,
                "--fault", "normal",
                "--fault", "offline",
                "--swan-base-url", "https://127.0.0.1:1",
                "--reference-base-url", "https://127.0.0.1:1",
                "--request-timeout-seconds", "0.2",
                "--no-fail-on-failure",
            ]
        )
        XCTAssertEqual(result.status, 0, String(decoding: result.stderr, as: UTF8.self))

        for suffix in ["normal", "offline"] {
            let path = outputDirectory.appending(path: "matrix-smoke-\(suffix).json")
            XCTAssertTrue(
                FileManager.default.fileExists(atPath: path.path),
                "Expected matrix artifact missing: \(path.lastPathComponent)"
            )
            let decoded = try JSONSerialization.jsonObject(with: Data(contentsOf: path), options: [])
            guard let artifact = decoded as? [String: Any] else {
                return XCTFail("artifact is not a dictionary: \(path.lastPathComponent)")
            }
            XCTAssertEqual(artifact["scenario"] as? String, "matrix-smoke-\(suffix)")
            XCTAssertEqual(artifact["faultModes"] as? [String], [suffix])
            if suffix == "normal" {
                XCTAssertTrue(
                    (artifact["status"] as? String) == "passed" || (artifact["status"] as? String) == "failed"
                )
            } else {
                XCTAssertEqual(artifact["status"] as? String, "passed")
            }
            XCTAssertNotNil(artifact["startedAt"])
            XCTAssertNotNil(artifact["completedAt"])
            if let hostResults = artifact["hostResults"] as? [[String: Any]] {
                XCTAssertEqual(hostResults.count, 2)
            } else {
                XCTFail("missing host results in \(path.lastPathComponent)")
            }
        }
    }

    func testLabMatrixRejectsUnknownFaultMode() throws {
        let outputDirectory = try temporaryDirectory().appending(path: "artifacts")
        try FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: outputDirectory) }

        let result = try runCLI(
            command: [
                "matrix",
                "--name", "matrix-smoke",
                "--fault", "time-travel",
                "--output-directory", outputDirectory.path,
            ]
        )
        XCTAssertNotEqual(result.status, 0)
        let combined = String(decoding: result.stdout, as: UTF8.self) + String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(combined.contains("unsupported lab fault mode"))
    }

    func testLabLiveRejectsUnknownModeBeforeReadingBody() throws {
        let result = try runCLI(
            command: [
                "live",
                "--mode", "unsupported",
                "--body-file", "/definitely/missing/live-body.json",
            ]
        )
        XCTAssertNotEqual(result.status, 0)
        let combined = String(decoding: result.stdout, as: UTF8.self) + String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(combined.contains("live mode must be public or permissioned"), combined)
    }

    func testLabLiveRejectsMetadataOnlyStatefulCombination() throws {
        let result = try runCLI(
            command: [
                "live",
                "--mode", "permissioned",
                "--permissioned-stateful-matrix",
                "--permissioned-list-ops-exclude-values",
                "--body-file", "/definitely/missing/live-body.json",
            ]
        )
        XCTAssertNotEqual(result.status, 0)
        let combined = String(decoding: result.stdout, as: UTF8.self) + String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(
            combined.contains("requires value-bearing listRepoOps"),
            combined
        )
    }

    func testLabLiveRejectsWriteOnlyApplyWritesReadFlagsBeforeBodyOrOAuth() throws {
        let result = try runCLI(
            command: [
                "live",
                "--mode", "permissioned",
                "--permissioned-write-only-apply-writes",
                "--permissioned-list-ops",
                "--body-file", "/definitely/missing/live-body.json",
            ]
        )
        XCTAssertNotEqual(result.status, 0)
        let combined = String(decoding: result.stdout, as: UTF8.self)
            + String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(
            combined.contains("write-only-apply-writes is incompatible"),
            combined
        )
        XCTAssertFalse(combined.contains("missing/live-body"), combined)
        XCTAssertFalse(combined.contains("OAuth"), combined)
    }

    func testLabLiveRejectsMalformedWriteOnlyBodyBeforeOAuth() throws {
        let body = try temporaryDirectory().appending(path: "malformed-apply-writes.json")
        defer { try? FileManager.default.removeItem(at: body) }
        try Data(
            #"{"space":"at://did:plc:abcdefghijklmnopqrstuvwx/space/app.bsky.bookmarks/a","repo":"did:plc:abcdefghijklmnopqrstuvwx","writes":[]}"#.utf8
        ).write(to: body)
        let result = try runCLI(
            command: [
                "live", "--mode", "permissioned",
                "--permissioned-write-only-apply-writes",
                "--space", "at://did:plc:abcdefghijklmnopqrstuvwx/space/app.bsky.bookmarks/a",
                "--repository", "did:plc:abcdefghijklmnopqrstuvwx",
                "--body-file", body.path,
            ]
        )
        XCTAssertNotEqual(result.status, 0)
        let combined = String(decoding: result.stdout, as: UTF8.self)
            + String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(combined.contains("pinned com.atproto.space.applyWrites"), combined)
        XCTAssertFalse(combined.contains("OAuth"), combined)
    }

    func testLabRecoverPermissionedRejectsInvalidReceiverBeforeNetwork() throws {
        let result = try runCLI(
            command: [
                "recover-permissioned",
                "--receiver-did", "not-a-did",
                "--repository", "did:plc:abcdefghijklmnopqrstuvwx",
                "--space", "at://did:plc:abcdefghijklmnopqrstuvwx/space/app.bsky.bookmarks/recovery",
                "--since", "2222222222222",
                "--data-directory", "/definitely/missing/swan-data",
            ]
        )
        XCTAssertNotEqual(result.status, 0)
        let combined = String(decoding: result.stdout, as: UTF8.self)
            + String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(
            combined.contains("--receiver-did is not a canonical DID"),
            combined
        )
    }

    func testLabSyncPermissionedRejectsInvalidReceiverBeforeNetwork() throws {
        let result = try runCLI(
            command: [
                "sync-permissioned",
                "--receiver-did", "not-a-did",
                "--repository", "did:plc:abcdefghijklmnopqrstuvwx",
                "--space", "at://did:plc:abcdefghijklmnopqrstuvwx/space/app.bsky.bookmarks/sync",
                "--data-directory", "/definitely/missing/swan-data",
            ]
        )
        XCTAssertNotEqual(result.status, 0)
        let combined = String(decoding: result.stdout, as: UTF8.self)
            + String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(
            combined.contains("--receiver-did is not a canonical DID"),
            combined
        )
        XCTAssertFalse(combined.contains("OAuth"), combined)
    }

    func testLabSyncPermissionedRejectsZeroSequenceBeforeNetwork() throws {
        let result = try runCLI(
            command: [
                "sync-permissioned",
                "--receiver-did", "did:plc:abcdefghijklmnopqrstuvwx",
                "--repository", "did:plc:zyxwvutsrqponmlkjihgfedc",
                "--space", "at://did:plc:abcdefghijklmnopqrstuvwx/space/app.bsky.bookmarks/sync",
                "--data-directory", "/definitely/missing/swan-data",
                "--request-sequence", "0",
            ]
        )
        XCTAssertNotEqual(result.status, 0)
        let combined = String(decoding: result.stdout, as: UTF8.self)
            + String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(
            combined.contains("--request-sequence must be positive"),
            combined
        )
        XCTAssertFalse(combined.contains("OAuth"), combined)
    }

    func testLabSyncPermissionedExposesExactDuplicateReplayProofMode() throws {
        let result = try runCLI(command: ["sync-permissioned", "--help"])
        let combined = String(decoding: result.stdout, as: UTF8.self)
            + String(decoding: result.stderr, as: UTF8.self)
        XCTAssertEqual(result.status, 0, combined)
        XCTAssertTrue(
            combined.contains("--verify-exact-duplicate-replay"),
            combined
        )
    }

    func testLabRecoverPermissionedRejectsInvalidRepositoryBeforeNetwork() throws {
        let result = try runCLI(
            command: [
                "recover-permissioned",
                "--receiver-did", "did:plc:abcdefghijklmnopqrstuvwx",
                "--repository", "not-a-did",
                "--space", "at://did:plc:abcdefghijklmnopqrstuvwx/space/app.bsky.bookmarks/recovery",
                "--since", "2222222222222",
                "--data-directory", "/definitely/missing/swan-data",
            ]
        )
        XCTAssertNotEqual(result.status, 0)
        let combined = String(decoding: result.stdout, as: UTF8.self)
            + String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(
            combined.contains("--repository is not a canonical DID"),
            combined
        )
    }

    func testLabRecoverPermissionedRejectsInvalidSpaceBeforeNetwork() throws {
        let result = try runCLI(
            command: [
                "recover-permissioned",
                "--receiver-did", "did:plc:abcdefghijklmnopqrstuvwx",
                "--repository", "did:plc:zyxwvutsrqponmlkjihgfedc",
                "--space", "not-a-space",
                "--since", "2222222222222",
                "--data-directory", "/definitely/missing/swan-data",
            ]
        )
        XCTAssertNotEqual(result.status, 0)
        let combined = String(decoding: result.stdout, as: UTF8.self)
            + String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(
            combined.contains("--space is not a valid space URI"),
            combined
        )
    }

    func testLabRecoverPermissionedRejectsUnauthenticatedSourceBeforeNetwork() throws {
        let result = try runCLI(
            command: [
                "recover-permissioned",
                "--receiver-did", "did:plc:abcdefghijklmnopqrstuvwx",
                "--repository", "did:plc:zyxwvutsrqponmlkjihgfedc",
                "--space", "at://did:plc:abcdefghijklmnopqrstuvwx/space/app.bsky.bookmarks/recovery",
                "--since", "2222222222222",
                "--source-auth", "none",
                "--data-directory", "/definitely/missing/swan-data",
            ]
        )
        XCTAssertNotEqual(result.status, 0)
        let combined = String(decoding: result.stdout, as: UTF8.self)
            + String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(
            combined.contains("--source-auth must be bearer or oauth"),
            combined
        )
    }

    func testLabLiveWritesSanitizedFailureArtifactWithoutNetwork() throws {
        let directory = try temporaryDirectory()
        let body = directory.appending(path: "record.json")
        let output = directory.appending(path: "live.json")
        try Data(#"{"repo":"did:plc:abcdefghijklmnopqrstuvwx","collection":"app.bsky.feed.post","rkey":"r1","record":{"text":"private fixture value"}}"#.utf8).write(to: body)

        let result = try runCLI(
            command: [
                "live",
                "--mode", "public",
                "--body-file", body.path,
                "--repository", "did:plc:abcdefghijklmnopqrstuvwx",
                "--collection", "app.bsky.feed.post",
                "--rkey", "r1",
                "--producer-url", "https://127.0.0.1:1",
                "--consumer-url", "https://127.0.0.1:1",
                "--request-timeout-seconds", "0.2",
                "--output", output.path,
                "--no-fail-on-failure",
            ]
        )
        XCTAssertEqual(result.status, 0, String(decoding: result.stderr, as: UTF8.self))
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: output)) as? [String: Any]
        )
        XCTAssertEqual(object["status"] as? String, "failed")
        let serialized = String(decoding: try Data(contentsOf: output), as: UTF8.self)
        XCTAssertFalse(serialized.contains("private fixture value"))
        XCTAssertFalse(serialized.contains("access_token"))
    }

    func testLabLiveFailureExitsNonzeroByDefault() throws {
        let directory = try temporaryDirectory()
        let body = directory.appending(path: "record.json")
        let output = directory.appending(path: "live.json")
        try Data(#"{"repo":"did:plc:abcdefghijklmnopqrstuvwx","collection":"app.bsky.feed.post","rkey":"r1","record":{"text":"failure fixture"}}"#.utf8).write(to: body)

        let result = try runCLI(
            command: [
                "live",
                "--mode", "public",
                "--body-file", body.path,
                "--repository", "did:plc:abcdefghijklmnopqrstuvwx",
                "--collection", "app.bsky.feed.post",
                "--rkey", "r1",
                "--producer-url", "https://127.0.0.1:1",
                "--consumer-url", "https://127.0.0.1:1",
                "--request-timeout-seconds", "0.2",
                "--output", output.path,
            ]
        )
        XCTAssertNotEqual(result.status, 0)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: output)) as? [String: Any]
        )
        XCTAssertEqual(object["status"] as? String, "failed")
        let combined = String(decoding: result.stdout, as: UTF8.self) + String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(combined.contains("live interoperability did not pass"), combined)
    }

    private func runCLI(command: [String]) throws -> (status: Int32, stdout: Data, stderr: Data) {
        let process = Process()
        process.executableURL = try XCTUnwrap(executableURL())
        process.arguments = ["lab"] + command
        var processEnvironment = ProcessInfo.processInfo.environment
        processEnvironment["SWAN_SCENARIO_SWAN_URL"] = "https://127.0.0.1:1"
        processEnvironment["SWAN_SCENARIO_REFERENCE_URL"] = "https://127.0.0.1:1"
        process.environment = processEnvironment
        process.environment?.merge([
            "SWAN_SCENARIO_SWAN_URL": "https://127.0.0.1:1",
            "SWAN_SCENARIO_REFERENCE_URL": "https://127.0.0.1:1",
        ]) { _, new in new }

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
        try FileManager.default.url(
            for: .itemReplacementDirectory,
            in: .userDomainMask,
            appropriateFor: FileManager.default.temporaryDirectory,
            create: true
        )
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
        // SwiftPM may place a scratch build under an arbitrary directory while
        // an older default `.build` product is still present.  Resolve the
        // product built beside this test bundle before considering that legacy
        // fallback so the suite cannot silently exercise stale CLI code.
        let coBuiltExecutable = Bundle(for: LabCLITests.self)
            .bundleURL
            .deletingLastPathComponent()
            .appending(path: "swan")
        if FileManager.default.isExecutableFile(
            atPath: coBuiltExecutable.path
        ) {
            return coBuiltExecutable
        }
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let executable = packageRoot.appending(path: ".build/debug/swan")
        guard FileManager.default.fileExists(atPath: executable.path) else {
            throw XCTSkip("swan executable not built at expected path")
        }
        return executable
    }

    private func repoRoot() -> URL {
        let file = URL(fileURLWithPath: #filePath)
        return file
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}
