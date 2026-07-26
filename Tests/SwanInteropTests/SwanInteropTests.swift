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
