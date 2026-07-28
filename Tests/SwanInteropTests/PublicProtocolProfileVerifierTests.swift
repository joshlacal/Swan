import Foundation
import XCTest
@testable import SwanInterop

final class PublicProtocolProfileVerifierTests: XCTestCase {
    func testCheckedInPublicProfileIsValid() throws {
        let root = packageRoot()
        let report = OfflineProtocolProfileVerifier.verify(
            profileURL: root.appending(path: "Profiles/public-data-testing-2026-07-27.json"),
            sourceRoot: root
        )
        XCTAssertEqual(report.profileID, OfflineProtocolProfileVerifier.publicProfileID)
        XCTAssertTrue(report.isValid, "\(report.diagnostics)")
    }

    func testPublicProfileRejectsMixedPermissionedSchemaAndEndpointReordering() throws {
        let fixture = try PublicProfileFixture()
        defer { fixture.remove() }
        try fixture.editProfile { profile in
            profile["proposalCommit"] = String(repeating: "0", count: 40)
            var endpoints = profile["endpoints"] as! [String]
            endpoints.swapAt(0, 1)
            profile["endpoints"] = endpoints
        }
        let report = OfflineProtocolProfileVerifier.verify(
            profileURL: fixture.profileURL,
            sourceRoot: fixture.root
        )
        XCTAssertTrue(report.diagnostics.contains(.init(.malformedProfile, artifact: "profile")))
        XCTAssertTrue(report.diagnostics.contains(.init(.immutableProfilePinMismatch, artifact: "profile")))
    }

    func testPublicProfileRejectsUppercaseChecksumAndUnknownID() throws {
        let fixture = try PublicProfileFixture()
        defer { fixture.remove() }
        try fixture.editProfile { profile in
            profile["id"] = "public-data-testing-unknown"
        }
        let report = OfflineProtocolProfileVerifier.verify(
            profileURL: fixture.profileURL,
            sourceRoot: fixture.root
        )
        XCTAssertEqual(report.diagnostics, [.init(.unsupportedProfileID, artifact: "profile")])
    }

    func testPublicProfileRejectsUppercaseChecksum() throws {
        let fixture = try PublicProfileFixture()
        defer { fixture.remove() }
        try fixture.editProfile { profile in
            profile["referenceArchiveSHA256"] =
                (profile["referenceArchiveSHA256"] as! String).uppercased()
        }
        let report = OfflineProtocolProfileVerifier.verify(
            profileURL: fixture.profileURL,
            sourceRoot: fixture.root
        )
        XCTAssertTrue(report.diagnostics.contains(
            .init(.invalidChecksumPin, artifact: "reference archive")
        ))
    }

    func testPublicProfileRejectsInjectedAndSymlinkedSwiftSources() throws {
        let fixture = try PublicProfileFixture()
        defer { fixture.remove() }
        let injected = fixture.root.appending(path: "Sources/SwanPublicWire/Injected.swift")
        try Data("// stale\n".utf8).write(to: injected)
        var report = OfflineProtocolProfileVerifier.verify(
            profileURL: fixture.profileURL,
            sourceRoot: fixture.root
        )
        XCTAssertTrue(report.diagnostics.contains(
            .init(.generatedWireSourceSetMismatch, artifact: "generated wire sources")
        ))

        try FileManager.default.removeItem(at: injected)
        let source = fixture.root.appending(
            path: "Sources/SwanPublicWire/Generated/Client/SwanPublicWireLexicons.swift"
        )
        let moved = fixture.root.appending(path: "real-source.swift")
        try FileManager.default.moveItem(at: source, to: moved)
        try FileManager.default.createSymbolicLink(at: source, withDestinationURL: moved)
        report = OfflineProtocolProfileVerifier.verify(
            profileURL: fixture.profileURL,
            sourceRoot: fixture.root
        )
        XCTAssertTrue(report.diagnostics.contains(
            .init(.generatedWireSourceSymlink, artifact: "generated wire source")
        ))
    }
}

private struct PublicProfileFixture {
    let root: URL
    let profileURL: URL

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "swan-public-profile-\(UUID().uuidString)", directoryHint: .isDirectory)
        let source = packageRoot()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.copyItem(
            at: source.appending(path: "Profiles"),
            to: root.appending(path: "Profiles")
        )
        try FileManager.default.createDirectory(
            at: root.appending(path: "Sources"),
            withIntermediateDirectories: true
        )
        try FileManager.default.copyItem(
            at: source.appending(path: "Sources/SwanPublicWire"),
            to: root.appending(path: "Sources/SwanPublicWire")
        )
        profileURL = root.appending(path: "Profiles/public-data-testing-2026-07-27.json")
    }

    func editProfile(_ edit: (inout [String: Any]) -> Void) throws {
        var profile = try JSONSerialization.jsonObject(with: Data(contentsOf: profileURL)) as! [String: Any]
        edit(&profile)
        let data = try JSONSerialization.data(withJSONObject: profile, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: profileURL)
    }

    func remove() {
        try? FileManager.default.removeItem(at: root)
    }
}

private func packageRoot(file: StaticString = #filePath) -> URL {
    URL(fileURLWithPath: "\(file)")
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
}
