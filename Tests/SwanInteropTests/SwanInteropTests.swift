import Foundation
import XCTest
import Crypto
@testable import SwanInterop

final class SwanInteropTests: XCTestCase {
    func testCheckedInProfileAndArtifactsVerifyOffline() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        let report = OfflineProtocolProfileVerifier.verify(
            profileURL: fixture.profileURL,
            sourceRoot: fixture.root
        )

        XCTAssertTrue(report.isValid, "\(report.diagnostics)")
        XCTAssertEqual(report.profileID, OfflineProtocolProfileVerifier.stableProfileID)
    }

    func testInvalidRevisionPinFailsWithTypedDiagnostic() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        try fixture.replaceInProfile(
            "1caad93dbb1f445396f6abf3b97eb4040345e78e",
            with: String(repeating: "g", count: 40)
        )

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .invalidRevisionPin })
    }

    func testUnexpectedButWellFormedPinFailsImmutableProfileVerification() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        try fixture.replaceInProfile(
            "3f6c96d5d2d25438bd40fa89d6ecc37865f8e354",
            with: String(repeating: "a", count: 40)
        )

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .immutableProfilePinMismatch })
    }

    func testLexiconManifestChecksumMismatchFailsOffline() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        try fixture.append("# mutated", to: fixture.lexiconManifestURL)

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertEqual(report.diagnostics, [.init(.lexiconManifestDigestMismatch, artifact: "lexicon manifest")])
    }

    func testMalformedProfileFailsWithoutLeakingItsContents() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        try Data("{ this is not JSON and contains secret-value }".utf8).write(to: fixture.profileURL)

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertEqual(report.diagnostics, [.init(.malformedProfile, artifact: "profile")])
        XCTAssertFalse(report.diagnostics[0].description.contains("secret-value"))
    }

    func testGeneratedWireSourceDriftFailsOffline() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        try fixture.append("\n// drift", to: fixture.generatedWireSourceURL)

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .generatedWireSourceChecksumMismatch })
    }

    func testUnexpectedGeneratedWireSourceFailsOffline() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        let unexpected = fixture.root.appending(path: "Sources/SwanSpacesWire/Generated/Injected.swift")
        try FileManager.default.createDirectory(at: unexpected.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("enum Injected {}".utf8).write(to: unexpected)

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .generatedWireSourceSetMismatch })
    }

    func testInternalGeneratedWireSymlinkFailsOffline() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        try fixture.replaceGeneratedWireSourceWithInternalSymlink()

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .generatedWireSourceSymlink })
    }

    func testDuplicateGeneratedWireManifestEntryIsRejected() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        let text = try String(contentsOf: fixture.generatedWireManifestURL, encoding: .utf8)
        let firstEntry = try XCTUnwrap(text.split(separator: "\n").first)
        try fixture.replaceGeneratedWireManifest(Data((text + "\(firstEntry)\n").utf8))

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .malformedGeneratedWireManifest })
    }

    func testUnsafeGeneratedWireManifestPathIsRejected() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        let text = try String(contentsOf: fixture.generatedWireManifestURL, encoding: .utf8)
        let mutated = text.replacingOccurrences(
            of: "Sources/SwanSpacesWire/Generated/",
            with: "Sources/SwanSpacesWire/Generated/../Generated/"
        )
        try fixture.replaceGeneratedWireManifest(Data(mutated.utf8))

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .malformedGeneratedWireManifest })
    }

    func testUppercaseGeneratedWireManifestChecksumIsRejected() throws {
        let fixture = try ProfileFixture()
        defer { fixture.remove() }

        let text = try String(contentsOf: fixture.generatedWireManifestURL, encoding: .utf8)
        let checksumEnd = try XCTUnwrap(text.firstIndex(of: " "))
        let lowercaseHex = try XCTUnwrap(text[..<checksumEnd].firstIndex(of: "a"))
        var mutated = text
        mutated.replaceSubrange(lowercaseHex...lowercaseHex, with: "A")
        try fixture.replaceGeneratedWireManifest(Data(mutated.utf8))

        let report = OfflineProtocolProfileVerifier.verify(profileURL: fixture.profileURL, sourceRoot: fixture.root)

        XCTAssertFalse(report.isValid)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .malformedGeneratedWireManifest })
    }

    func testLaboratoryCacheRequiresMatchingArchiveAndPDSSource() throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "swan-lab-cache-\(UUID().uuidString)", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let archiveData = Data("pinned archive fixture".utf8)
        let archiveDigest = SHA256.hash(data: archiveData).map { String(format: "%02x", $0) }.joined()
        let pin = ReferenceSourcePin(
            repository: URL(string: "https://example.invalid/reference")!,
            commit: "fixture",
            archiveSHA256: archiveDigest
        )
        try archiveData.write(to: root.appending(path: "atproto-fixture.tar.gz"))
        let source = root.appending(path: "atproto-fixture", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(
            at: source.appending(path: "services/pds", directoryHint: .isDirectory),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: source.appending(path: "packages/pds", directoryHint: .isDirectory),
            withIntermediateDirectories: true
        )
        for path in ["package.json", "pnpm-lock.yaml", "services/pds/Dockerfile", "packages/pds/package.json"] {
            try Data("{}".utf8).write(to: source.appending(path: path))
        }

        XCTAssertTrue(InteropLaboratory.validate(cacheDirectory: root, pin: pin).isValid)

        try Data("mutated".utf8).write(to: root.appending(path: "atproto-fixture.tar.gz"))
        XCTAssertEqual(
            InteropLaboratory.validate(cacheDirectory: root, pin: pin).diagnostics,
            [.invalidReferenceArchive]
        )
    }

    func testSanitizedScenarioArtifactHasNoCredentialFields() throws {
        let artifact = try SanitizedScenarioArtifact(
            scenario: "reference-matrix",
            faultModes: [.delayed, .corrupted]
        )
        let encoded = try JSONEncoder().encode(artifact)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        let keys = Set(object.keys.map { $0.lowercased() })
        XCTAssertTrue(keys.isDisjoint(with: ["password", "authorization", "access_token", "refresh_token", "dpop", "private_key", "ikm"]))
        XCTAssertEqual(object["status"] as? String, "planned-not-executed")
        XCTAssertTrue((object["fixturePolicy"] as? String ?? "").hasPrefix("summary-only"))
    }

    func testDuplicatedFaultModeProbesEachEndpointTwice() async throws {
        let runtime = InteropScenarioRunner.RuntimeConfiguration(
            swanBaseURL: URL(string: "https://127.0.0.1:1")!,
            referenceBaseURL: URL(string: "https://127.0.0.1:1")!,
            timeoutInterval: 0.2
        )
        let artifact = await InteropScenarioRunner.execute(
            scenario: "duplication-matrix",
            faultModes: [.duplicated],
            runtime: runtime
        )
        XCTAssertEqual(artifact.faultModes, ["duplicated"])
        XCTAssertEqual(artifact.hostResults.count, 2)

        for host in artifact.hostResults {
            let grouped = Dictionary(grouping: host.endpointResults, by: \.path)
            XCTAssertTrue(
                grouped.values.allSatisfy { $0.count == 2 },
                "Expected duplicated probe to produce two requests per endpoint on \(host.host)"
            )
            XCTAssertTrue(
                host.endpointResults.contains(where: { $0.transportError == "network" }),
                "Expected duplicated probe to include network failure on unreachable test host for \(host.host)"
            )
        }
    }

    func testReorderedFaultModeReversesEndpointExecutionOrder() async throws {
        let runtime = InteropScenarioRunner.RuntimeConfiguration(
            swanBaseURL: URL(string: "https://127.0.0.1:1")!,
            referenceBaseURL: URL(string: "https://127.0.0.1:1")!,
            timeoutInterval: 0.2
        )
        let normal = await InteropScenarioRunner.execute(
            scenario: "baseline-matrix",
            faultModes: [],
            runtime: runtime
        )
        let reordered = await InteropScenarioRunner.execute(
            scenario: "reordered-matrix",
            faultModes: [.reordered],
            runtime: runtime
        )

        XCTAssertEqual(normal.hostResults.count, 2)
        XCTAssertEqual(reordered.hostResults.count, 2)

        for (normalHost, reorderedHost) in zip(normal.hostResults, reordered.hostResults) {
            let normalPaths = normalHost.endpointResults.map(\.path)
            let reorderedPaths = reorderedHost.endpointResults.map(\.path)
            XCTAssertEqual(reorderedPaths.count, normalPaths.count)
            XCTAssertEqual(reorderedPaths, normalPaths.reversed(), "\(normalHost.host) and \(reorderedHost.host) order should be reversed")
        }
    }

    func testCorruptedFaultModeCapturesUnsuccessfulCorruptionVariants() async throws {
        let runtime = InteropScenarioRunner.RuntimeConfiguration(
            swanBaseURL: URL(string: "https://127.0.0.1:1")!,
            referenceBaseURL: URL(string: "https://127.0.0.1:1")!,
            timeoutInterval: 0.2
        )
        let artifact = await InteropScenarioRunner.execute(
            scenario: "corruption-matrix",
            faultModes: [.corrupted],
            runtime: runtime
        )
        XCTAssertEqual(artifact.faultModes, ["corrupted"])

        for host in artifact.hostResults {
            let grouped = Dictionary(grouping: host.endpointResults, by: \.path)
            XCTAssertTrue(
                grouped.values.allSatisfy { $0.count == 2 },
                "Expected corrupted fault mode to include baseline and malformed request for each endpoint on \(host.host)"
            )
            XCTAssertTrue(
                host.endpointResults.contains {
                    $0.mode == "corrupted" &&
                    ($0.responseSummary["status"] != nil || $0.responseSummary["error"] != nil)
                }
            )
        }
    }

    func testInteropScenarioRunnerSummarizesCrossHostConvergence() async throws {
        let runtime = InteropScenarioRunner.RuntimeConfiguration(
            swanBaseURL: URL(string: "https://127.0.0.1:1")!,
            referenceBaseURL: URL(string: "https://127.0.0.1:1")!,
            timeoutInterval: 0.2
        )
        let artifact = await InteropScenarioRunner.execute(
            scenario: "convergence-matrix",
            faultModes: [],
            runtime: runtime
        )

        XCTAssertFalse(artifact.convergence.isEmpty)
        let describe = artifact.convergence.first {
            $0.path == "/xrpc/com.atproto.server.describeServer" && $0.mode == "normal"
        }
        XCTAssertNotNil(describe)
        XCTAssertGreaterThan(describe!.swanProbeCount, 0)
        XCTAssertEqual(describe!.swanProbeCount, describe!.referenceProbeCount)
        XCTAssertEqual(describe!.swanTransportError, true)
        XCTAssertEqual(describe!.referenceTransportError, true)
    }

    func testConvergenceSummaryDetectsStrictMismatch() {
        let key = InteropScenarioRunner.EndpointResultKey(mode: "normal", method: "GET", path: "/xrpc/com.atproto.server.describeServer")
        let buckets: [String: [InteropScenarioRunner.EndpointResultKey: [EndpointResult]]] = [
            "swan": [
                key: [
                    EndpointResult(
                        mode: "normal",
                        method: "GET",
                        path: "/xrpc/com.atproto.server.describeServer",
                        statusCode: 200,
                        requestSummary: ["host": "swan"],
                        responseSummary: ["status": "200"]
                    )
                ]
            ],
            "reference-pds": [
                key: [
                    EndpointResult(
                        mode: "normal",
                        method: "GET",
                        path: "/xrpc/com.atproto.server.describeServer",
                        statusCode: 503,
                        requestSummary: ["host": "pds"],
                        responseSummary: ["status": "503", "error": "temporarily_unavailable"]
                    )
                ]
            ],
        ]

        var unexpectedFailure = false
        var warnings: [String] = []
        let convergence = InteropScenarioRunner.summarizeCrossHostConvergence(
            from: buckets,
            strictConvergence: true,
            allowedConvergenceDivergences: [],
            hasUnexpectedFailure: &unexpectedFailure,
            warnings: &warnings
        )

        XCTAssertEqual(convergence.count, 1)
        XCTAssertFalse(convergence[0].firstProbeAligned)
        XCTAssertFalse(convergence[0].allowedMismatch)
        XCTAssertTrue(unexpectedFailure)
        XCTAssertEqual(warnings.count, 1)
    }

    func testConvergenceSummaryAllowsConfiguredMismatch() {
        let key = InteropScenarioRunner.EndpointResultKey(mode: "normal", method: "GET", path: "/xrpc/com.atproto.server.describeServer")
        let buckets: [String: [InteropScenarioRunner.EndpointResultKey: [EndpointResult]]] = [
            "swan": [
                key: [
                    EndpointResult(
                        mode: "normal",
                        method: "GET",
                        path: "/xrpc/com.atproto.server.describeServer",
                        statusCode: 200,
                        requestSummary: ["host": "swan"],
                        responseSummary: ["status": "200"]
                    )
                ]
            ],
            "reference-pds": [
                key: [
                    EndpointResult(
                        mode: "normal",
                        method: "GET",
                        path: "/xrpc/com.atproto.server.describeServer",
                        statusCode: 503,
                        requestSummary: ["host": "pds"],
                        responseSummary: ["status": "503", "error": "temporarily_unavailable"]
                    )
                ]
            ],
        ]

        var unexpectedFailure = false
        var warnings: [String] = []
        let convergence = InteropScenarioRunner.summarizeCrossHostConvergence(
            from: buckets,
            strictConvergence: true,
            allowedConvergenceDivergences: ["/xrpc/com.atproto.server.describeServer"],
            hasUnexpectedFailure: &unexpectedFailure,
            warnings: &warnings
        )

        XCTAssertEqual(convergence.count, 1)
        XCTAssertTrue(convergence[0].allowedMismatch)
        XCTAssertFalse(unexpectedFailure)
        XCTAssertTrue(warnings.isEmpty)
    }

    func testInteropScenarioRunnerProducesSanitizedProbeFixture() async throws {
        let runtime = InteropScenarioRunner.RuntimeConfiguration(
            swanBaseURL: URL(string: "https://127.0.0.1:1")!,
            referenceBaseURL: URL(string: "https://127.0.0.1:1")!,
            timeoutInterval: 0.2
        )
        let artifact = await InteropScenarioRunner.execute(
            scenario: "reference-matrix",
            faultModes: [.offline, .corrupted],
            runtime: runtime
        )
        XCTAssertEqual(artifact.scenario, "reference-matrix")
        XCTAssertEqual(artifact.faultModes, ["offline", "corrupted"])
        XCTAssertEqual(artifact.status, "failed")
        XCTAssertEqual(artifact.hostResults.count, 2)
        let encoded = try JSONEncoder().encode(artifact)
        let decoded = try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        let forbidden: Set<String> = ["password", "authorization", "access_token", "refresh_token", "dpop", "private_key", "ikm"]
        let containsForbidden = decoded.flatMap {
            Self.sanitizedKeys(in: $0).contains { key in
                forbidden.contains(where: { key.lowercased().contains($0) })
            }
        } ?? false
        XCTAssertFalse(containsForbidden)
    }

    func testDisconnectedFaultModeIsAcceptedInScenarioExecution() async throws {
        let runtime = InteropScenarioRunner.RuntimeConfiguration(
            swanBaseURL: URL(string: "https://127.0.0.1:1")!,
            referenceBaseURL: URL(string: "https://127.0.0.1:1")!,
            timeoutInterval: 0.2
        )
        let artifact = await InteropScenarioRunner.execute(
            scenario: "disconnect-matrix",
            faultModes: [.disconnected],
            runtime: runtime
        )
        XCTAssertEqual(artifact.faultModes, ["disconnected"])
        XCTAssertEqual(artifact.hostResults.count, 2)
        XCTAssertEqual(artifact.status, "passed")
        for host in artifact.hostResults {
            XCTAssertTrue(host.endpointResults.contains { $0.transportError == "network" })
        }
    }

    func testLocalSemanticInteropExercisesDurableConvergenceRecoveryAndIsolation() async throws {
        let artifact = await LocalSemanticInteropRunner.execute(
            scenario: "local-semantic-matrix"
        )

        XCTAssertEqual(artifact.implementation, "swan-durable-to-swan-durable")
        XCTAssertEqual(artifact.status, "passed", "\(artifact)")
        XCTAssertEqual(artifact.operationCount, 4)
        XCTAssertEqual(artifact.recordCount, 1)
        XCTAssertEqual(artifact.checks.count, 18)
        XCTAssertTrue(artifact.checks.allSatisfy(\.passed))
        XCTAssertNotNil(artifact.sourceCommitment)
        XCTAssertEqual(artifact.sourceCommitment, artifact.consumerCommitment)
        XCTAssertEqual(artifact.sourceCommitment, artifact.fullRecoveryCommitment)
        XCTAssertNotNil(artifact.carDigest)
        XCTAssertNil(artifact.errorCode)

        let encoded = try JSONEncoder().encode(artifact)
        let decoded = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        let forbidden: Set<String> = [
            "password", "authorization", "access_token", "refresh_token",
            "dpop", "private_key", "ikm", "secret", "record_value",
        ]
        XCTAssertFalse(
            Self.sanitizedKeys(in: decoded).contains { key in
                forbidden.contains(where: { key.lowercased().contains($0) })
            }
        )
    }

    private static func sanitizedKeys(in value: Any) -> [String] {
        switch value {
        case let object as [String: Any]:
            return object.keys.flatMap { key in
                [key] + sanitizedKeys(in: object[key]!)
            }
        case let array as [Any]:
            return array.flatMap(sanitizedKeys(in:))
        default:
            return []
        }
    }
}

private final class ProfileFixture {
    let root: URL
    let profileURL: URL
    let lexiconManifestURL: URL
    let generatedWireManifestURL: URL
    let generatedWireSourceURL: URL

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "swan-profile-verifier-\(UUID().uuidString)", directoryHint: .isDirectory)
        let profiles = root.appending(path: "Profiles", directoryHint: .isDirectory)
        let sources = root.appending(path: "Sources", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: profiles, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: sources, withIntermediateDirectories: true)

        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let profileName = "permissioned-data-0016-2026-07-03.json"
        let lexiconName = "permissioned-data-0016-2026-07-03.lexicons.sha256"
        profileURL = profiles.appending(path: profileName)
        lexiconManifestURL = profiles.appending(path: lexiconName)
        generatedWireManifestURL = profiles.appending(path: "permissioned-data-0016-2026-07-03.generated-wire.sha256")
        generatedWireSourceURL = sources.appending(path: "SwanSpacesWire/SwanSpacesWire.swift")

        try FileManager.default.copyItem(
            at: packageRoot.appending(path: "Profiles/\(profileName)"),
            to: profileURL
        )
        try FileManager.default.copyItem(
            at: packageRoot.appending(path: "Profiles/\(lexiconName)"),
            to: lexiconManifestURL
        )
        try FileManager.default.copyItem(
            at: packageRoot.appending(path: "Profiles/permissioned-data-0016-2026-07-03.generated-wire.sha256"),
            to: generatedWireManifestURL
        )
        try FileManager.default.copyItem(
            at: packageRoot.appending(path: "Sources/SwanSpacesWire"),
            to: sources.appending(path: "SwanSpacesWire", directoryHint: .isDirectory)
        )
    }

    func replaceInProfile(_ old: String, with new: String) throws {
        let text = try String(contentsOf: profileURL, encoding: .utf8)
        XCTAssertTrue(text.contains(old))
        try text.replacingOccurrences(of: old, with: new).data(using: .utf8)!.write(to: profileURL)
    }

    func append(_ text: String, to url: URL) throws {
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        try handle.seekToEnd()
        try handle.write(contentsOf: Data(text.utf8))
    }

    func replaceGeneratedWireManifest(_ data: Data) throws {
        try data.write(to: generatedWireManifestURL)
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        try replaceInProfile(
            "c1d5697f351a4209c7f8a9faaf460d423f9f44f37845ae2c92e150e78c552609",
            with: digest
        )
    }

    func replaceGeneratedWireSourceWithInternalSymlink() throws {
        let trustedTarget = root.appending(path: "TrustedGeneratedWire.swift")
        try FileManager.default.copyItem(at: generatedWireSourceURL, to: trustedTarget)
        try FileManager.default.removeItem(at: generatedWireSourceURL)
        try FileManager.default.createSymbolicLink(at: generatedWireSourceURL, withDestinationURL: trustedTarget)
    }

    func remove() {
        try? FileManager.default.removeItem(at: root)
    }
}
