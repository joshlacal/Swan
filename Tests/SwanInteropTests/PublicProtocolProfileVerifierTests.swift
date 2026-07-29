import Foundation
import Crypto
import XCTest
@testable import SwanInterop

final class PublicProtocolProfileVerifierTests: XCTestCase {
    func testCheckedInPublicProfileIsValid() throws {
        let root = packageRoot()
        let report = OfflineProtocolProfileVerifier.verify(
            profileURL: root.appending(path: "Profiles/public-data-testing-2026-07-30.json"),
            sourceRoot: root
        )
        XCTAssertEqual(report.profileID, OfflineProtocolProfileVerifier.publicProfileID)
        XCTAssertTrue(report.isValid, "\(report.diagnostics)")
    }

    func testLegacyPublicProfileRemainsByteExactButIsNoLongerSelected() throws {
        let root = packageRoot()
        let legacyArtifacts = [
            ("public-data-testing-2026-07-27.json", "6effa7604b1c2613f6819a6c4bb7d21874bd5073db23556089060c495a3c91bf"),
            ("public-data-testing-2026-07-27.lexicons.sha256", "bd94660a2c2c05fc23185059329194ff6c29635f74ce2efcf97351c1be98fe97"),
            ("public-data-testing-2026-07-27.generated-wire.sha256", "c68177a315f6a3d6f01419f48be5e0beedf76d1e4ae21ebe5de52ac49ad80d3b"),
        ]
        for (name, checksum) in legacyArtifacts {
            let data = try Data(contentsOf: root.appending(path: "Profiles/\(name)"))
            XCTAssertEqual(SHA256.hash(data: data).hex, checksum)
        }

        let report = OfflineProtocolProfileVerifier.verify(
            profileURL: root.appending(path: "Profiles/public-data-testing-2026-07-27.json"),
            sourceRoot: root
        )
        XCTAssertEqual(report.profileID, "public-data-testing-2026-07-27")
        XCTAssertEqual(
            report.diagnostics,
            [.init(.unsupportedProfileID, artifact: "profile")]
        )
    }

    func testPublicProfileRejectsLexiconEndpointConfusion() throws {
        let fixture = try PublicProfileFixture()
        defer { fixture.remove() }
        try fixture.editProfile { profile in
            profile["endpoints"] = profile["lexicons"]
        }
        let report = OfflineProtocolProfileVerifier.verify(
            profileURL: fixture.profileURL,
            sourceRoot: fixture.root
        )
        XCTAssertTrue(report.diagnostics.contains(.init(.malformedProfile, artifact: "profile")))
        XCTAssertTrue(report.diagnostics.contains(
            .init(.immutableProfilePinMismatch, artifact: "profile")
        ))
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

    func testPublicProfileRejectsNonemptyDivergenceSemanticDrift() throws {
        let fixture = try PublicProfileFixture()
        defer { fixture.remove() }
        try fixture.editProfile { profile in
            var divergences = profile["intentionalDivergences"] as! [[String: Any]]
            divergences[0]["swanBehavior"] = "Still nonempty, but no longer the frozen behavior."
            profile["intentionalDivergences"] = divergences
        }
        let report = OfflineProtocolProfileVerifier.verify(
            profileURL: fixture.profileURL,
            sourceRoot: fixture.root
        )
        XCTAssertTrue(report.diagnostics.contains(
            .init(.immutableProfilePinMismatch, artifact: "profile")
        ))
    }

    func testPublicProfileRejectsMissingServerGeneratedSource() throws {
        let fixture = try PublicProfileFixture()
        defer { fixture.remove() }
        try FileManager.default.removeItem(
            at: fixture.root.appending(
                path: "Sources/SwanPublicWire/Generated/Lexicons/Com/Atproto/ComAtprotoServerConfirmEmail.swift"
            )
        )
        let report = OfflineProtocolProfileVerifier.verify(
            profileURL: fixture.profileURL,
            sourceRoot: fixture.root
        )
        XCTAssertTrue(report.diagnostics.contains(
            .init(.generatedWireSourceMissing, artifact: "generated wire source")
        ))
        XCTAssertTrue(report.diagnostics.contains(
            .init(.generatedWireSourceSetMismatch, artifact: "generated wire sources")
        ))
    }

    func testPublicProfileRejectsStaleGeneratedManifestHash() throws {
        let fixture = try PublicProfileFixture()
        defer { fixture.remove() }
        try fixture.editProfile { profile in
            profile["generatedWireManifestSHA256"] =
                "c68177a315f6a3d6f01419f48be5e0beedf76d1e4ae21ebe5de52ac49ad80d3b"
        }
        let report = OfflineProtocolProfileVerifier.verify(
            profileURL: fixture.profileURL,
            sourceRoot: fixture.root
        )
        XCTAssertTrue(report.diagnostics.contains(
            .init(.immutableProfilePinMismatch, artifact: "profile")
        ))
        XCTAssertTrue(report.diagnostics.contains(
            .init(.generatedWireManifestDigestMismatch, artifact: "generated wire manifest")
        ))
    }

    func testPublicProfileRejectsStalePetrelManifestBytes() throws {
        let fixture = try PublicProfileFixture()
        defer { fixture.remove() }
        try Data("{\"stale\":true}\n".utf8).write(
            to: fixture.root.appending(path: "PublicPetrelManifest.json")
        )
        let report = OfflineProtocolProfileVerifier.verify(
            profileURL: fixture.profileURL,
            sourceRoot: fixture.root
        )
        XCTAssertTrue(report.diagnostics.contains(
            .init(.immutableProfilePinMismatch, artifact: "Petrel manifest")
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
            at: source.appending(path: "PublicPetrelManifest.json"),
            to: root.appending(path: "PublicPetrelManifest.json")
        )
        try FileManager.default.copyItem(
            at: source.appending(path: "Sources/SwanPublicWire"),
            to: root.appending(path: "Sources/SwanPublicWire")
        )
        profileURL = root.appending(path: "Profiles/public-data-testing-2026-07-30.json")
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

private extension SHA256.Digest {
    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

private func packageRoot(file: StaticString = #filePath) -> URL {
    URL(fileURLWithPath: "\(file)")
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
}
