import Crypto
import Foundation
import Petrel
@testable import SwanAccountExport
import SwanAccounts
import SwanPublicRepository
import SwanSQLite
import SwanSpaces
import SwanSpacesWire
import SwanStorage
import XCTest

final class SwanPortableExportTests: XCTestCase {
    private let handle = "alice.example.com"
    private let profileID = PermissionedData0016.profileID

    func testVerifierAcceptsCanonicalArchiveAndChecksBothCARTypes() throws {
        let fixture = try ArchiveFixture()
        defer { fixture.remove() }

        let manifest = try SwanPortableExportVerifier.verifyArchive(
            at: fixture.root,
            signingPublicKey: fixture.key.publicKey
        )

        XCTAssertEqual(manifest.format, "swan-account-export-v2")
        XCTAssertEqual(manifest.profileID, profileID)
        XCTAssertEqual(manifest.did, fixture.did)
        XCTAssertEqual(manifest.canonicalHandle, handle)
        XCTAssertEqual(manifest.plcHistoryScope, "locally-retained-genesis")
        XCTAssertFalse(manifest.includesPrivateKeys)
        XCTAssertEqual(manifest.files.map(\.path), manifest.files.map(\.path).sorted())
        XCTAssertEqual(Set(manifest.files.map(\.type)), [.publicCAR, .spaceCAR, .plcHistory])
    }

    func testVerifierRejectsUnknownManifestFieldsAndNoncanonicalPaths() throws {
        let fixture = try ArchiveFixture()
        defer { fixture.remove() }
        let manifestURL = fixture.root.appending(path: "manifest.json")
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: manifestURL)) as? [String: Any]
        )
        object["privateKey"] = "must-not-be-tolerated"
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            .write(to: manifestURL)

        XCTAssertThrowsError(
            try SwanPortableExportVerifier.verifyArchive(
                at: fixture.root,
                signingPublicKey: fixture.key.publicKey
            )
        )

        object.removeValue(forKey: "privateKey")
        var files = try XCTUnwrap(object["files"] as? [[String: Any]])
        files[0]["path"] = "../repository.car"
        object["files"] = files
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            .write(to: manifestURL)
        XCTAssertThrowsError(
            try SwanPortableExportVerifier.verifyArchive(
                at: fixture.root,
                signingPublicKey: fixture.key.publicKey
            )
        )
    }

    func testVerifierRejectsPLCHistoryThatNamesADifferentPublicGenesis() throws {
        let fixture = try ArchiveFixture()
        defer { fixture.remove() }
        let historyURL = fixture.root.appending(path: "plc/history.json")
        var history = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: historyURL)) as? [String: Any]
        )
        history["publicGenesisCommitCID"] =
            "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        let historyData = try JSONSerialization.data(
            withJSONObject: history,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        try historyData.write(to: historyURL)

        let manifestURL = fixture.root.appending(path: "manifest.json")
        var manifest = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: manifestURL)) as? [String: Any]
        )
        var files = try XCTUnwrap(manifest["files"] as? [[String: Any]])
        let historyIndex = try XCTUnwrap(
            files.firstIndex { $0["path"] as? String == "plc/history.json" }
        )
        files[historyIndex]["byteCount"] = historyData.count
        files[historyIndex]["sha256"] = SwanPortableExportDigest.hex(historyData)
        manifest["files"] = files
        try JSONSerialization.data(
            withJSONObject: manifest,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ).write(to: manifestURL)

        XCTAssertThrowsError(
            try SwanPortableExportVerifier.verifyArchive(
                at: fixture.root,
                signingPublicKey: fixture.key.publicKey
            )
        )
    }

    func testManifestCodecRejectsNoncanonicalJSONBytes() throws {
        let fixture = try ArchiveFixture()
        defer { fixture.remove() }
        let manifestURL = fixture.root.appending(path: "manifest.json")
        let canonical = try Data(contentsOf: manifestURL)
        let duplicateKey = Data(#"{"format":"swan-account-export-v2","#.utf8)
            + canonical.dropFirst()
        let leadingEntry = Data(#"{"canonicalHandle":"alice.example.com","#.utf8)
        let unsorted = Data("{".utf8)
            + canonical.dropFirst(leadingEntry.count).dropLast()
            + Data(#","canonicalHandle":"alice.example.com"}"#.utf8)

        for noncanonical in [
            Data(" \n".utf8) + canonical,
            canonical + Data("\n".utf8),
            duplicateKey,
            unsorted,
        ] {
            try noncanonical.write(to: manifestURL)
            XCTAssertThrowsError(
                try SwanPortableExportVerifier.verifyArchive(
                    at: fixture.root,
                    signingPublicKey: fixture.key.publicKey
                )
            )
        }
    }

    func testVerifierRejectsMissingAndMalformedCARsAndBlobs() async throws {
        let fixture = try await ExporterFixture()
        defer { fixture.remove() }
        let exported = try await fixture.export(named: "complete")
        let manifest = try SwanPortableExportVerifier.verifyArchive(
            at: exported.output,
            signingPublicKey: fixture.signingKey.publicKey
        )

        for type in [
            SwanPortableExportFileType.publicCAR,
            .spaceCAR,
            .publicBlob,
            .spaceBlob,
        ] {
            let entry = try XCTUnwrap(manifest.files.first { $0.type == type })

            let missing = fixture.root.appending(path: "missing-\(type.rawValue)")
            try FileManager.default.copyItem(at: exported.output, to: missing)
            try FileManager.default.removeItem(at: missing.appending(path: entry.path))
            XCTAssertThrowsError(
                try SwanPortableExportVerifier.verifyArchive(
                    at: missing,
                    signingPublicKey: fixture.signingKey.publicKey
                ),
                "missing \(type.rawValue) must fail"
            )

            let malformed = fixture.root.appending(path: "malformed-\(type.rawValue)")
            try FileManager.default.copyItem(at: exported.output, to: malformed)
            let malformedBytes = Data("malformed-\(type.rawValue)".utf8)
            try malformedBytes.write(to: malformed.appending(path: entry.path))
            try replaceManifestEntry(entry, data: malformedBytes, archive: malformed)
            XCTAssertThrowsError(
                try SwanPortableExportVerifier.verifyArchive(
                    at: malformed,
                    signingPublicKey: fixture.signingKey.publicKey
                ),
                "malformed \(type.rawValue) must fail after digest is updated"
            )
        }
    }

    func testVerifierRejectsUnexpectedDirectory() throws {
        let fixture = try ArchiveFixture()
        defer { fixture.remove() }
        try FileManager.default.createDirectory(
            at: fixture.root.appending(path: "unexpected"),
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        XCTAssertThrowsError(
            try SwanPortableExportVerifier.verifyArchive(
                at: fixture.root,
                signingPublicKey: fixture.key.publicKey
            )
        )
    }

    func testVerifierRejectsPLCAtprotoKeyDifferentFromCARSigningKey() throws {
        let fixture = try ArchiveFixture(crossedPLCSigningKey: true)
        defer { fixture.remove() }

        XCTAssertThrowsError(
            try SwanPortableExportVerifier.verifyArchive(
                at: fixture.root,
                signingPublicKey: fixture.key.publicKey
            )
        )
    }

    func testExporterPublishesFreshVerifiedArchiveWithSeparatedBlobNamespaces() async throws {
        let fixture = try await ExporterFixture()
        defer { fixture.remove() }

        let first = try await fixture.export(named: "first")
        let second = try await fixture.export(named: "second")
        let firstManifest = try SwanPortableExportVerifier.verifyArchive(
            at: first.output,
            signingPublicKey: fixture.signingKey.publicKey
        )
        let secondManifest = try SwanPortableExportVerifier.verifyArchive(
            at: second.output,
            signingPublicKey: fixture.signingKey.publicKey
        )

        XCTAssertEqual(firstManifest.files.filter { $0.type == .spaceCAR }.count, 2)
        XCTAssertEqual(
            firstManifest.files.filter { $0.type == .publicBlob }.map(\.path).count,
            2
        )
        XCTAssertEqual(
            firstManifest.files.filter { $0.type == .spaceBlob }.map(\.path).count,
            2
        )
        let publicBlobCIDs = try Set(firstManifest.files.filter { $0.type == .publicBlob }.map {
            try SwanPortableExportPath.decode(String($0.path.split(separator: "/").last!))
        })
        let spaceBlobCIDs = try Set(firstManifest.files.filter { $0.type == .spaceBlob }.map {
            try SwanPortableExportPath.decode(String($0.path.split(separator: "/").last!))
        })
        XCTAssertEqual(publicBlobCIDs.intersection(spaceBlobCIDs).count, 1)
        XCTAssertNotEqual(first.result.manifestSHA256, second.result.manifestSHA256)
        let firstSpaceCARs = try firstManifest.files
            .filter { $0.type == .spaceCAR }
            .map { try Data(contentsOf: first.output.appending(path: $0.path)) }
        let secondSpaceCARs = try secondManifest.files
            .filter { $0.type == .spaceCAR }
            .map { try Data(contentsOf: second.output.appending(path: $0.path)) }
        XCTAssertNotEqual(firstSpaceCARs, secondSpaceCARs)

        let archiveBytes = try allFileBytes(under: first.output)
        for sentinel in fixture.secretSentinels {
            XCTAssertNil(archiveBytes.range(of: sentinel))
        }

        let collision = fixture.root.appending(path: "collision")
        try FileManager.default.createDirectory(
            at: collision,
            withIntermediateDirectories: false
        )
        await XCTAssertThrowsErrorAsync {
            _ = try await fixture.export(to: collision)
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: collision.path), [])

        let symlinkTarget = fixture.root.appending(path: "symlink-target")
        let symlinkOutput = fixture.root.appending(path: "symlink-output")
        try FileManager.default.createDirectory(at: symlinkTarget, withIntermediateDirectories: false)
        try FileManager.default.createSymbolicLink(
            atPath: symlinkOutput.path,
            withDestinationPath: symlinkTarget.path
        )
        await XCTAssertThrowsErrorAsync {
            _ = try await fixture.export(to: symlinkOutput)
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: symlinkTarget.path), [])
    }

    func testSuccessfulCLIPrintsOnlyPublicResultAndLeavesAccountAndKeySourcesUnchanged() async throws {
        let fixture = try await ExporterFixture()
        defer { fixture.remove() }
        let control = try await SQLiteControlDatabase(dataDirectory: fixture.root)
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: fixture.account.did,
                canonicalHandle: fixture.account.canonicalHandle,
                passwordVerifier: portableExportTestVerifier,
                signingKey: try XCTUnwrap(fixture.account.signingKey),
                rotationKey: try XCTUnwrap(fixture.account.rotationKey),
                publicGenesisCommitCID: fixture.account.publicGenesisCommitCID
            )
        )
        try await control.close()

        let operatorSecret = Data("portable-export-operator-secret".utf8)
        let rawKEK = Data(repeating: 0xA7, count: 32)
        let encodedKEK = rawKEK.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let operatorURL = fixture.root.appending(path: "operator-secret")
        let kekURL = fixture.root.appending(path: "account-kek")
        try protectedWrite(operatorSecret, to: operatorURL)
        try protectedWrite(Data(encodedKEK.utf8), to: kekURL)
        let output = fixture.root.appending(path: "cli-export")
        let sourceBefore = try selectedSourceSnapshot(fixture.root)

        let process = Process()
        process.executableURL = try XCTUnwrap(swanExecutableURL())
        process.arguments = [
            "export",
            "--data-directory", fixture.root.path,
            "--did", fixture.account.did,
            "--output-directory", output.path,
            "--operator-secret-file", operatorURL.path,
            "--account-kek-file", kekURL.path,
            "--account-key-directory", fixture.root.appending(path: "keys").path,
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

        XCTAssertEqual(process.terminationStatus, 0)
        XCTAssertTrue(errorBytes.isEmpty)
        let result = try JSONDecoder().decode(SwanPortableExportResult.self, from: outputBytes)
        XCTAssertEqual(result.did, fixture.account.did)
        XCTAssertEqual(result.outputDirectory, output.path)
        XCTAssertFalse(result.includesPrivateKeys)
        let outputObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: outputBytes) as? [String: Any]
        )
        XCTAssertEqual(
            Set(outputObject.keys),
            ["did", "fileCount", "includesPrivateKeys", "manifestSHA256", "outputDirectory"]
        )
        for secret in fixture.secretSentinels + [operatorSecret, rawKEK, Data(encodedKEK.utf8)] {
            XCTAssertNil(outputBytes.range(of: secret))
            XCTAssertNil(errorBytes.range(of: secret))
        }
        _ = try SwanPortableExportVerifier.verifyArchive(
            at: output,
            signingPublicKey: fixture.signingKey.publicKey
        )
        XCTAssertEqual(try selectedSourceSnapshot(fixture.root), sourceBefore)

        let reopenedControl = try await SQLiteControlDatabase(
            dataDirectory: fixture.root,
            openMode: .existingPortableExportSource
        )
        let updatedAccount = try await reopenedControl.account(did: fixture.account.did)
        XCTAssertEqual(updatedAccount?.export?.reference, result.manifestSHA256)
        try await reopenedControl.close()
    }

    func testMidExportFailureCleansStagingAndDoesNotMutateSource() async throws {
        let fixture = try await ExporterFixture()
        defer { fixture.remove() }
        let before = try await fixture.database.portableExportInventory()
        let output = fixture.root.appending(path: "failed")
        let exporter = try SwanPortableAccountExporter(
            database: fixture.database,
            keyStore: fixture.keyStore,
            now: { Date(timeIntervalSince1970: 1_700_000_000) },
            afterArtifactWrite: { count in
                if count == 2 {
                    throw SwanPortableExportError.publicationFailed
                }
            }
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await exporter.export(account: fixture.account, to: output)
        }

        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        XCTAssertFalse(
            try FileManager.default.contentsOfDirectory(atPath: fixture.root.path)
                .contains { $0.hasPrefix(".swan-export-") }
        )
        let after = try await fixture.database.portableExportInventory()
        XCTAssertEqual(after, before)
    }

    func testPostRenamePreSyncFailureRemovesInstalledOutputAndAllowsSafeRetry() async throws {
        let fixture = try await ExporterFixture()
        defer { fixture.remove() }
        let output = fixture.root.appending(path: "post-rename-failure")
        let faultedExporter = try SwanPortableAccountExporter(
            database: fixture.database,
            keyStore: fixture.keyStore,
            afterRenameBeforeParentSync: {
                throw SwanPortableExportError.publicationFailed
            }
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await faultedExporter.export(account: fixture.account, to: output)
        }

        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        XCTAssertFalse(
            try FileManager.default.contentsOfDirectory(atPath: fixture.root.path)
                .contains { $0.hasPrefix(".swan-export-") }
        )

        let retried = try await fixture.export(to: output)
        XCTAssertEqual(retried.outputDirectory, output.path)
        _ = try SwanPortableExportVerifier.verifyArchive(
            at: output,
            signingPublicKey: fixture.signingKey.publicKey
        )
    }

    func testParentReplacementDuringPublicationCannotRedirectOrOrphanStaging() async throws {
        let fixture = try await ExporterFixture()
        defer { fixture.remove() }
        let parent = fixture.root.appending(path: "exports")
        let movedParent = fixture.root.appending(path: "exports-moved")
        let output = parent.appending(path: "archive")
        try FileManager.default.createDirectory(
            at: parent,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let exporter = try SwanPortableAccountExporter(
            database: fixture.database,
            keyStore: fixture.keyStore,
            afterArtifactWrite: { count in
                guard count == 1 else { return }
                try FileManager.default.moveItem(at: parent, to: movedParent)
                try FileManager.default.createDirectory(
                    at: parent,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700]
                )
            }
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await exporter.export(account: fixture.account, to: output)
        }

        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: parent.path), [])
        XCTAssertFalse(
            try FileManager.default.contentsOfDirectory(atPath: movedParent.path)
                .contains { $0.hasPrefix(".swan-export-") || $0 == "archive" }
        )
    }

    func testMissingJournalAndInactiveAccountNeverPublish() async throws {
        let fixture = try await ExporterFixture(includeJournal: false)
        defer { fixture.remove() }
        let missingJournalOutput = fixture.root.appending(path: "missing-journal")
        await XCTAssertThrowsErrorAsync {
            _ = try await fixture.export(to: missingJournalOutput)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: missingJournalOutput.path))

        let inactive = try AccountControlAccount(
            did: fixture.account.did,
            canonicalHandle: fixture.account.canonicalHandle,
            status: .deactivated,
            createdAt: fixture.account.createdAt,
            updatedAt: fixture.account.updatedAt,
            credentialState: fixture.account.credentialState,
            signingKey: fixture.account.signingKey,
            rotationKey: fixture.account.rotationKey,
            publicGenesisCommitCID: fixture.account.publicGenesisCommitCID
        )
        let inactiveOutput = fixture.root.appending(path: "inactive")
        let exporter = try SwanPortableAccountExporter(
            database: fixture.database,
            keyStore: fixture.keyStore
        )
        await XCTAssertThrowsErrorAsync {
            _ = try await exporter.export(account: inactive, to: inactiveOutput)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: inactiveOutput.path))
    }

    private func allFileBytes(under root: URL) throws -> Data {
        var output = Data()
        let enumerator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)!
        for case let url as URL in enumerator where !url.hasDirectoryPath {
            output.append(try Data(contentsOf: url))
        }
        return output
    }

    private func replaceManifestEntry(
        _ replaced: SwanPortableExportFile,
        data: Data,
        archive: URL
    ) throws {
        let manifestURL = archive.appending(path: "manifest.json")
        let current = try SwanPortableExportManifestCodec.decode(Data(contentsOf: manifestURL))
        let files = try current.files.map { entry in
            guard entry.path == replaced.path else { return entry }
            return try SwanPortableExportFile(
                path: entry.path,
                byteCount: data.count,
                sha256: SwanPortableExportDigest.hex(data),
                type: entry.type
            )
        }
        let rewritten = try SwanPortableExportManifest(
            profileID: current.profileID,
            did: current.did,
            canonicalHandle: current.canonicalHandle,
            createdAt: current.createdAt,
            files: files
        )
        try SwanPortableExportManifestCodec.encode(rewritten).write(to: manifestURL)
    }

    private func protectedWrite(_ data: Data, to url: URL) throws {
        try data.write(to: url)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: url.path
        )
    }

    private func swanExecutableURL() -> URL? {
        if let configured = ProcessInfo.processInfo.environment["SWAN_TEST_EXECUTABLE"] {
            let candidate = URL(fileURLWithPath: configured)
            if FileManager.default.isExecutableFile(atPath: candidate.path) {
                return candidate
            }
        }
        let packageRoot = URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        for candidate in [
            packageRoot.appending(path: ".build-task19/debug/swan"),
            packageRoot.appending(path: ".build/debug/swan"),
        ] where FileManager.default.isExecutableFile(atPath: candidate.path) {
            return candidate
        }
        return nil
    }

    private func selectedSourceSnapshot(_ root: URL) throws -> [String: Data] {
        var result: [String: Data] = [:]
        for source in ["actors", "keys"] {
            let sourceRoot = root.appending(path: source)
            let enumerator = try XCTUnwrap(
                FileManager.default.enumerator(
                    at: sourceRoot,
                    includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey],
                    options: [],
                    errorHandler: nil
                )
            )
            for case let url as URL in enumerator {
                let relative = String(url.path.dropFirst(root.path.count + 1))
                let values = try url.resourceValues(
                    forKeys: [.isDirectoryKey, .isRegularFileKey]
                )
                let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
                let mode = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
                if values.isDirectory == true {
                    result[relative] = Data("directory:\(mode)".utf8)
                } else if values.isRegularFile == true {
                    var value = Data("file:\(mode):".utf8)
                    // SQLite's shared-memory file contains transient reader
                    // lock bytes. Durable source immutability is asserted over
                    // the database, WAL, outbox rows, blobs, and key envelopes;
                    // for `-shm`, assert identity/shape without treating
                    // ephemeral reader locks as repository writes.
                    if url.lastPathComponent.hasSuffix(".sqlite-shm") {
                        let size = (attributes[.size] as? NSNumber)?.uint64Value ?? 0
                        value.append(Data("shared-memory:\(size)".utf8))
                    } else {
                        value.append(try Data(contentsOf: url))
                    }
                    result[relative] = value
                }
            }
        }
        return result
    }
}

final class SwanPortableRestoreTests: XCTestCase {
    func testSelfContainedVerificationDerivesPLCSigningKeyAndRejectsCorruption() async throws {
        let fixture = try ArchiveFixture()
        defer { fixture.remove() }

        let verified = try SwanPortableExportVerifier.verifyArchive(at: fixture.root)
        XCTAssertEqual(verified.manifest.did, fixture.did)
        XCTAssertEqual(
            verified.signingPublicKey.compressedRepresentation,
            fixture.key.publicKey.compressedRepresentation
        )
        let manifestData = try Data(
            contentsOf: fixture.root.appending(path: "manifest.json")
        )
        XCTAssertEqual(
            verified.manifestSHA256,
            "sha256:\(SwanPortableExportDigest.hex(manifestData))"
        )

        let crossed = try ArchiveFixture(crossedPLCSigningKey: true)
        defer { crossed.remove() }
        XCTAssertThrowsError(try SwanPortableExportVerifier.verifyArchive(at: crossed.root))

        for type in [
            SwanPortableExportFileType.publicCAR,
            .spaceCAR,
        ] {
            let archive = try copiedArchive(fixture.root, named: type.rawValue)
            defer { try? FileManager.default.removeItem(at: archive) }
            let manifest = try manifest(at: archive)
            let entry = try XCTUnwrap(manifest.files.first { $0.type == type })
            let corrupted = Data("corrupted-\(type.rawValue)".utf8)
            try corrupted.write(to: archive.appending(path: entry.path))
            try rewriteManifestEntry(entry, data: corrupted, archive: archive)
            XCTAssertThrowsError(
                try SwanPortableExportVerifier.verifyArchive(at: archive),
                "\(type.rawValue) corruption must fail after its checksum is replaced"
            )
        }

        let exportedFixture = try await ExporterFixture()
        defer { exportedFixture.remove() }
        let exported = try await exportedFixture.export(named: "restore-source")
        let exportedManifest = try manifest(at: exported.output)
        let blobEntry = try XCTUnwrap(
            exportedManifest.files.first { $0.type == .publicBlob }
        )
        let badBlob = Data("corrupted-blob".utf8)
        try badBlob.write(to: exported.output.appending(path: blobEntry.path))
        try rewriteManifestEntry(blobEntry, data: badBlob, archive: exported.output)
        XCTAssertThrowsError(
            try SwanPortableExportVerifier.verifyArchive(at: exported.output)
        )

        let noncanonical = try copiedArchive(fixture.root, named: "noncanonical")
        defer { try? FileManager.default.removeItem(at: noncanonical) }
        let manifestURL = noncanonical.appending(path: "manifest.json")
        try (try Data(contentsOf: manifestURL) + Data("\n".utf8)).write(to: manifestURL)
        XCTAssertThrowsError(try SwanPortableExportVerifier.verifyArchive(at: noncanonical))

        let privateIndication = try copiedArchive(fixture.root, named: "private")
        defer { try? FileManager.default.removeItem(at: privateIndication) }
        let privateManifestURL = privateIndication.appending(path: "manifest.json")
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: Data(contentsOf: privateManifestURL)
            ) as? [String: Any]
        )
        object["includesPrivateKeys"] = true
        try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ).write(to: privateManifestURL)
        XCTAssertThrowsError(
            try SwanPortableExportVerifier.verifyArchive(at: privateIndication)
        )
    }

    func testStagingCopiesExactVerifiedTreeWithOwnerOnlyModesAndNoActivationState() throws {
        let fixture = try ArchiveFixture()
        defer { fixture.remove() }
        let dataDirectory = try temporaryDirectory(named: "data")
        defer { try? FileManager.default.removeItem(at: dataDirectory.deletingLastPathComponent()) }
        let verification = try SwanPortableExportVerifier.verifyArchive(at: fixture.root)

        let result = try SwanPortableAccountRestoreStager().stage(
            archiveAt: fixture.root,
            dataDirectory: dataDirectory
        )

        XCTAssertEqual(result.status, .staged)
        XCTAssertEqual(result.did, verification.manifest.did)
        XCTAssertEqual(result.canonicalHandle, verification.manifest.canonicalHandle)
        XCTAssertEqual(result.fileCount, verification.manifest.files.count)
        XCTAssertFalse(result.includesPrivateKeys)
        XCTAssertEqual(result.manifestSHA256, verification.manifestSHA256)
        XCTAssertEqual(result.profileID, PermissionedData0016.profileID)
        let staged = URL(fileURLWithPath: result.stagingDirectory)
        XCTAssertEqual(try treeSnapshot(fixture.root), try treeSnapshot(staged))
        _ = try SwanPortableExportVerifier.verifyArchive(at: staged)
        XCTAssertEqual(try directoryMode(dataDirectory), 0o700)
        XCTAssertEqual(
            try directoryMode(dataDirectory.appending(path: "restore-staging")),
            0o700
        )
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: dataDirectory.appending(path: "control.sqlite").path
        ))
        for forbidden in ["actors", "keys", "oauth", "sessions"] {
            XCTAssertFalse(FileManager.default.fileExists(
                atPath: dataDirectory.appending(path: forbidden).path
            ))
        }
    }

    func testInvalidSourceCreatesNoStateAndExistingStageIsIdempotentButOccupiedTargetsFail()
        throws
    {
        let fixture = try ArchiveFixture()
        defer { fixture.remove() }
        let root = try temporaryDirectory(named: "root")
        defer { try? FileManager.default.removeItem(at: root.deletingLastPathComponent()) }
        let invalid = try copiedArchive(fixture.root, named: "invalid-source")
        defer { try? FileManager.default.removeItem(at: invalid) }
        try Data("bad".utf8).write(to: invalid.appending(path: "public/repository.car"))

        XCTAssertThrowsError(
            try SwanPortableAccountRestoreStager().stage(
                archiveAt: invalid,
                dataDirectory: root
            )
        )
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: root.appending(path: "restore-staging").path
        ))

        let first = try SwanPortableAccountRestoreStager().stage(
            archiveAt: fixture.root,
            dataDirectory: root
        )
        let before = try treeSnapshot(URL(fileURLWithPath: first.stagingDirectory))
        let second = try SwanPortableAccountRestoreStager().stage(
            archiveAt: fixture.root,
            dataDirectory: root
        )
        XCTAssertEqual(second.status, .alreadyStaged)
        XCTAssertEqual(
            try treeSnapshot(URL(fileURLWithPath: second.stagingDirectory)),
            before
        )

        try FileManager.default.removeItem(at: URL(fileURLWithPath: first.stagingDirectory))
        try Data("occupied".utf8).write(to: URL(fileURLWithPath: first.stagingDirectory))
        XCTAssertThrowsError(
            try SwanPortableAccountRestoreStager().stage(
                archiveAt: fixture.root,
                dataDirectory: root
            )
        )
        XCTAssertEqual(
            try Data(contentsOf: URL(fileURLWithPath: first.stagingDirectory)),
            Data("occupied".utf8)
        )

        try FileManager.default.removeItem(at: URL(fileURLWithPath: first.stagingDirectory))
        let symlinkTarget = root.appending(path: "symlink-target")
        try FileManager.default.createDirectory(
            at: symlinkTarget,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.createSymbolicLink(
            atPath: first.stagingDirectory,
            withDestinationPath: symlinkTarget.path
        )
        XCTAssertThrowsError(
            try SwanPortableAccountRestoreStager().stage(
                archiveAt: fixture.root,
                dataDirectory: root
            )
        )
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: symlinkTarget.path), [])
    }

    func testPostRenamePreSyncFailureCleansInstalledStageAndAllowsRetry() throws {
        let fixture = try ArchiveFixture()
        defer { fixture.remove() }
        let dataDirectory = try temporaryDirectory(named: "fault-data")
        defer { try? FileManager.default.removeItem(at: dataDirectory.deletingLastPathComponent()) }
        let verification = try SwanPortableExportVerifier.verifyArchive(at: fixture.root)
        let hash = String(verification.manifestSHA256.dropFirst("sha256:".count))
        let installed = dataDirectory
            .appending(path: "restore-staging")
            .appending(path: hash)

        XCTAssertThrowsError(
            try SwanPortableAccountRestoreStager(afterRenameBeforeParentSync: {
                throw SwanPortableExportError.publicationFailed
            }).stage(archiveAt: fixture.root, dataDirectory: dataDirectory)
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: installed.path))
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: dataDirectory.appending(path: "restore-staging").path
        ))

        let retried = try SwanPortableAccountRestoreStager().stage(
            archiveAt: fixture.root,
            dataDirectory: dataDirectory
        )
        XCTAssertEqual(retried.status, .staged)
        _ = try SwanPortableExportVerifier.verifyArchive(
            at: URL(fileURLWithPath: retried.stagingDirectory)
        )
    }

    func testRestoreParentReplacementFailsAndCannotRedirectAdvertisedStage() throws {
        let fixture = try ArchiveFixture()
        defer { fixture.remove() }
        let dataDirectory = try temporaryDirectory(named: "replacement-data")
        defer { try? FileManager.default.removeItem(at: dataDirectory.deletingLastPathComponent()) }
        let restoreParent = dataDirectory.appending(path: "restore-staging")
        let displacedParent = dataDirectory.appending(path: "restore-staging-displaced")
        try FileManager.default.createDirectory(
            at: restoreParent,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let stager = SwanPortableAccountRestoreStager(
            beforeSuccessIdentityValidation: {
                try FileManager.default.moveItem(
                    at: restoreParent,
                    to: displacedParent
                )
                try FileManager.default.createDirectory(
                    at: restoreParent,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700]
                )
            }
        )

        XCTAssertThrowsError(
            try stager.stage(
                archiveAt: fixture.root,
                dataDirectory: dataDirectory
            )
        )

        XCTAssertEqual(
            try FileManager.default.contentsOfDirectory(atPath: restoreParent.path),
            []
        )
        XCTAssertEqual(
            try FileManager.default.contentsOfDirectory(atPath: displacedParent.path),
            []
        )
    }

    func testIntermediateDirectorySyncFailureCleansAllRestoreState() throws {
        let fixture = try ArchiveFixture()
        defer { fixture.remove() }
        let dataDirectory = try temporaryDirectory(named: "sync-failure-data")
        defer { try? FileManager.default.removeItem(at: dataDirectory.deletingLastPathComponent()) }
        let recorder = RestoreFaultRecorder()
        let stager = SwanPortableAccountRestoreStager(
            synchronizeCreatedDirectoryParent: { _ in
                recorder.record(1)
                throw SwanPortableExportError.publicationFailed
            }
        )

        XCTAssertThrowsError(
            try stager.stage(
                archiveAt: fixture.root,
                dataDirectory: dataDirectory
            )
        )

        XCTAssertEqual(recorder.values, [1])
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: dataDirectory.appending(path: "restore-staging").path
        ))
    }

    func testTransientCleanupFailureIsRetriedAndAbsenceIsVerified() throws {
        let fixture = try ArchiveFixture()
        defer { fixture.remove() }
        let dataDirectory = try temporaryDirectory(named: "cleanup-failure-data")
        defer { try? FileManager.default.removeItem(at: dataDirectory.deletingLastPathComponent()) }
        let verification = try SwanPortableExportVerifier.verifyArchive(at: fixture.root)
        let hash = String(verification.manifestSHA256.dropFirst("sha256:".count))
        let recorder = RestoreFaultRecorder()
        let stager = SwanPortableAccountRestoreStager(
            afterRenameBeforeParentSync: {
                throw SwanPortableExportError.publicationFailed
            },
            beforeCleanupAttempt: { attempt in
                recorder.record(attempt)
                if attempt == 1 {
                    throw SwanPortableExportError.publicationFailed
                }
            }
        )

        XCTAssertThrowsError(
            try stager.stage(
                archiveAt: fixture.root,
                dataDirectory: dataDirectory
            )
        )

        XCTAssertEqual(recorder.values, [1, 2])
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: dataDirectory
                .appending(path: "restore-staging")
                .appending(path: hash)
                .path
        ))
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: dataDirectory.appending(path: "restore-staging").path
        ))
    }

    func testDataDirectoryMustAlreadyBeAnOwnerOnlyUnlinkedDirectory() throws {
        let fixture = try ArchiveFixture()
        defer { fixture.remove() }
        let parent = try temporaryDirectory(named: "placement-parent")
        defer { try? FileManager.default.removeItem(at: parent.deletingLastPathComponent()) }
        let missing = parent.appending(path: "missing")
        XCTAssertThrowsError(
            try SwanPortableAccountRestoreStager().stage(
                archiveAt: fixture.root,
                dataDirectory: missing
            )
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: missing.path))

        let broad = parent.appending(path: "broad")
        try FileManager.default.createDirectory(
            at: broad,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o755]
        )
        XCTAssertThrowsError(
            try SwanPortableAccountRestoreStager().stage(
                archiveAt: fixture.root,
                dataDirectory: broad
            )
        )
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: broad.path), [])

        let target = parent.appending(path: "target")
        let linked = parent.appending(path: "linked")
        try FileManager.default.createDirectory(
            at: target,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.createSymbolicLink(
            atPath: linked.path,
            withDestinationPath: target.path
        )
        XCTAssertThrowsError(
            try SwanPortableAccountRestoreStager().stage(
                archiveAt: fixture.root,
                dataDirectory: linked
            )
        )
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: target.path), [])
    }

    private func temporaryDirectory(named name: String) throws -> URL {
        let parent = FileManager.default.temporaryDirectory
            .appending(path: "SwanPortableRestore-\(UUID().uuidString)")
        let directory = parent.appending(path: name)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: parent.path
        )
        return directory
    }

    private func copiedArchive(_ source: URL, named name: String) throws -> URL {
        let output = source.deletingLastPathComponent()
            .appending(path: "SwanPortableRestore-\(name)-\(UUID().uuidString)")
        try FileManager.default.copyItem(at: source, to: output)
        return output
    }

    private func manifest(at archive: URL) throws -> SwanPortableExportManifest {
        try SwanPortableExportManifestCodec.decode(
            Data(contentsOf: archive.appending(path: "manifest.json"))
        )
    }

    private func rewriteManifestEntry(
        _ replaced: SwanPortableExportFile,
        data: Data,
        archive: URL
    ) throws {
        let current = try manifest(at: archive)
        let files = try current.files.map { entry in
            guard entry.path == replaced.path else { return entry }
            return try SwanPortableExportFile(
                path: entry.path,
                byteCount: data.count,
                sha256: SwanPortableExportDigest.hex(data),
                type: entry.type
            )
        }
        let rewritten = try SwanPortableExportManifest(
            profileID: current.profileID,
            did: current.did,
            canonicalHandle: current.canonicalHandle,
            createdAt: current.createdAt,
            files: files
        )
        try SwanPortableExportManifestCodec.encode(rewritten).write(
            to: archive.appending(path: "manifest.json")
        )
    }

    private func directoryMode(_ url: URL) throws -> UInt16 {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        return (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
    }

    private func treeSnapshot(_ root: URL) throws -> [String: Data] {
        var output: [String: Data] = [:]
        try collectTree(root: root, relative: "", output: &output)
        return output
    }

    private func collectTree(
        root: URL,
        relative: String,
        output: inout [String: Data]
    ) throws {
        for name in try FileManager.default.contentsOfDirectory(atPath: root.path).sorted() {
            let url = root.appending(path: name)
            let childRelative = relative.isEmpty ? name : "\(relative)/\(name)"
            let values = try url.resourceValues(
                forKeys: [.isDirectoryKey, .isRegularFileKey]
            )
            let mode = try directoryMode(url)
            if values.isDirectory == true {
                output[childRelative] = Data("directory:\(mode)".utf8)
                try collectTree(root: url, relative: childRelative, output: &output)
            } else if values.isRegularFile == true {
                var value = Data("file:\(mode):".utf8)
                value.append(try Data(contentsOf: url))
                output[childRelative] = value
            }
        }
    }
}

private final class RestoreFaultRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [Int] = []

    var values: [Int] {
        lock.withLock { storage }
    }

    func record(_ value: Int) {
        lock.withLock {
            storage.append(value)
        }
    }
}

private struct ExporterFixture {
    let root: URL
    let database: SQLiteAccountDatabase
    let keyStore: FileAccountKeyStore
    let account: AccountControlAccount
    let signingKey: P256.Signing.PrivateKey
    let secretSentinels: [Data]

    init(includeJournal: Bool = true) async throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPortableExporter-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let handle = "alice.example.com"
        signingKey = P256.Signing.PrivateKey()
        let rotationKey = P256.Signing.PrivateKey()
        let unsignedPLC = try PLCATProfile.regularOperation(
            handle: handle,
            signingPublicKey: signingKey.publicKey,
            rotationPublicKeys: [rotationKey.publicKey],
            pdsOrigin: URL(string: "https://pds.example.com")!,
            prev: nil
        )
        let plc = try PLCOperationCodec.sign(.regular(unsignedPLC), using: rotationKey)
        let did = try PLCOperationCodec.genesisDID(for: plc)
        let rawKEK = Data(repeating: 0xA7, count: 32)
        let keyConfiguration = try AccountKeyEncryptionConfiguration(
            activeKeyID: "primary",
            activeKey: rawKEK
        )
        keyStore = try FileAccountKeyStore(
            root: root.appending(path: "keys"),
            configuration: keyConfiguration
        )
        let signingReference = try AccountKeyReference(
            accountDID: did,
            purpose: .signing,
            generation: 1
        )
        let rotationReference = try AccountKeyReference(
            accountDID: did,
            purpose: .rotation,
            generation: 1
        )
        try await keyStore.createBatch([
            try .init(reference: signingReference, key: signingKey.rawRepresentation),
            try .init(reference: rotationReference, key: rotationKey.rawRepresentation),
        ])
        database = try await SQLiteAccountDatabase(dataDirectory: root, did: did)
        let genesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: "3jzfcijpj2z2a",
            signingKey: signingKey
        )
        _ = try await database.installPublicRepositoryGenesis(
            genesis,
            signingPublicKey: signingKey.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let signingControl = try AccountControlKeyReference(
            purpose: .signing,
            generation: 1
        )
        let rotationControl = try AccountControlKeyReference(
            purpose: .rotation,
            generation: 1
        )
        let initialJournal = try PLCAccountPreparationJournal(
            requestID: "portable-export-test",
            canonicalHandle: handle,
            pdsOrigin: "https://pds.example.com",
            repositoryRevision: genesis.revision,
            operation: try .init(
                signingDIDKey: try XCTUnwrap(plc.regular?.verificationMethods["atproto"]),
                rotationDIDKey: try XCTUnwrap(plc.regular?.rotationKeys.only),
                signature: try XCTUnwrap(plc.regular?.signature)
            ),
            signingKey: signingControl,
            rotationKey: rotationControl,
            publicGenesisCommitCID: nil,
            stage: .keysStored
        )
        if includeJournal {
            _ = try await database.installPLCAccountPreparationJournal(initialJournal)
            _ = try await database.advancePLCAccountPreparationJournal(
                requestID: initialJournal.requestID,
                expectedStage: .keysStored,
                to: .repositoryInstalled,
                publicGenesisCommitCID: genesis.commitCID.string
            )
            _ = try await database.advancePLCAccountPreparationJournal(
                requestID: initialJournal.requestID,
                expectedStage: .repositoryInstalled,
                to: .submissionPending,
                publicGenesisCommitCID: nil
            )
            _ = try await database.advancePLCAccountPreparationJournal(
                requestID: initialJournal.requestID,
                expectedStage: .submissionPending,
                to: .submitted,
                publicGenesisCommitCID: nil
            )
        }
        let timestamp = Date(timeIntervalSince1970: 1_700_000_000)
        account = try AccountControlAccount(
            did: did,
            canonicalHandle: handle,
            status: .active,
            createdAt: timestamp,
            updatedAt: timestamp,
            credentialState: .configured,
            signingKey: signingControl,
            rotationKey: rotationControl,
            publicGenesisCommitCID: genesis.commitCID.string
        )

        for (index, skey) in ["first", "second"].enumerated() {
            let space = try SpaceURI(
                authority: did,
                spaceType: "app.bsky.bookmarks",
                skey: skey
            )
            let repository = try DurableSpaceRepository(
                database: database,
                space: space,
                author: did
            )
            let uri = try SpaceRecordURI(
                space: space,
                author: did,
                collection: "app.bsky.feed.post",
                rkey: "record-\(index)"
            )
            _ = try await repository.apply(
                .put(uri: uri, value: Data([0xa1, 0x61, 0x78, UInt8(index)])),
                expectedRevision: 0,
                requestID: UUID(),
                wireRevision: try TID(tidString: "3jzfcijpj2z\(index + 2)a"),
                authorization: .accountOAuth(subject: did, scopes: ["atproto"])
            )
        }
        let firstSpace = try SpaceURI(
            authority: did,
            spaceType: "app.bsky.bookmarks",
            skey: "first"
        )
        _ = try await database.putBlob(Data("public-body".utf8), namespace: .public)
        _ = try await database.putBlob(Data("space-body".utf8), namespace: .space(firstSpace))
        let aliasedPhysicalBlob = Data("shared-body".utf8)
        _ = try await database.putBlob(aliasedPhysicalBlob, namespace: .public)
        _ = try await database.putBlob(aliasedPhysicalBlob, namespace: .space(firstSpace))
        secretSentinels = [
            rawKEK,
            signingKey.rawRepresentation,
            rotationKey.rawRepresentation,
            Data("raw-password-sentinel".utf8),
            Data("$argon2id$verifier-sentinel".utf8),
            Data("operator-secret-sentinel".utf8),
            Data("oauth-token-sentinel".utf8),
            Data("dns-http-sentinel".utf8),
            Data("SQLite format 3".utf8),
        ]
    }

    func export(named: String) async throws -> (
        output: URL,
        result: SwanPortableExportResult
    ) {
        let output = root.appending(path: named)
        return (output, try await export(to: output))
    }

    func export(to output: URL) async throws -> SwanPortableExportResult {
        let exporter = try SwanPortableAccountExporter(
            database: database,
            keyStore: keyStore,
            now: { Date(timeIntervalSince1970: 1_700_000_000) }
        )
        return try await exporter.export(account: account, to: output)
    }

    func remove() {
        Task { try? await database.close() }
        try? FileManager.default.removeItem(at: root)
    }
}

private extension Array {
    var only: Element? { count == 1 ? first : nil }
}

private func XCTAssertThrowsErrorAsync(
    _ expression: () async throws -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        try await expression()
        XCTFail("expected error", file: file, line: line)
    } catch {}
}

private struct ArchiveFixture {
    let root: URL
    let key: P256.Signing.PrivateKey
    let did: String

    init(crossedPLCSigningKey: Bool = false) throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPortableExportVerifier-\(UUID().uuidString)")
        key = P256.Signing.PrivateKey()
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )

        let plcSigningKey = crossedPLCSigningKey
            ? P256.Signing.PrivateKey().publicKey
            : key.publicKey
        let operation = try PLCFixture.makeGenesis(
            handle: "alice.example.com",
            signingPublicKey: plcSigningKey
        )
        did = try PLCOperationCodec.genesisDID(for: operation)
        let publicGenesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: "3jzfcijpj2z2a",
            signingKey: key
        )
        try write(publicGenesis.car, path: "public/repository.car")

        let space = try SpaceURI(
            authority: did,
            spaceType: "app.bsky.bookmarks",
            skey: "saved"
        )
        let recordURI = try SpaceRecordURI(
            space: space,
            author: did,
            collection: "app.bsky.feed.post",
            rkey: "one"
        )
        let recordValue = Data([0xa1, 0x61, 0x78, 0x01])
        var state = LtHash()
        let cid = CID.fromDAGCBOR(recordValue).string
        state.add(element: "\(recordURI.collection)/\(recordURI.rkey)/\(cid)")
        let commit = try SpaceCommitCodec.createReaderEnvelope(
            space: space,
            author: did,
            rev: "3jzfcijpj2z2b",
            commitment: state.commitment,
            key: key
        )
        let car = try SpaceCARCodec.encode(
            commit: commit,
            records: [.init(uri: recordURI, value: recordValue, cid: cid, revision: 1)]
        )
        try write(
            car.data,
            path: "spaces/\(SwanPortableExportPath.encode(space.rawValue))/\(SwanPortableExportPath.encode(did)).car"
        )

        let history = try PLCFixture.historyJSON(
            operation: operation,
            did: did,
            repositoryRevision: publicGenesis.revision,
            publicGenesisCommitCID: publicGenesis.commitCID.string
        )
        try write(history, path: "plc/history.json")

        let payloads: [(String, SwanPortableExportFileType, Data)] = [
            ("plc/history.json", .plcHistory, history),
            ("public/repository.car", .publicCAR, publicGenesis.car),
            (
                "spaces/\(SwanPortableExportPath.encode(space.rawValue))/\(SwanPortableExportPath.encode(did)).car",
                .spaceCAR,
                car.data
            ),
        ]
        let manifest = try SwanPortableExportManifest(
            profileID: PermissionedData0016.profileID,
            did: did,
            canonicalHandle: "alice.example.com",
            createdAt: "2026-07-27T12:34:56.000Z",
            files: payloads.map {
                try SwanPortableExportFile(
                    path: $0.0,
                    byteCount: $0.2.count,
                    sha256: SwanPortableExportDigest.hex($0.2),
                    type: $0.1
                )
            }.sorted { $0.path < $1.path }
        )
        let manifestURL = root.appending(path: "manifest.json")
        FileManager.default.createFile(
            atPath: manifestURL.path,
            contents: try SwanPortableExportManifestCodec.encode(manifest),
            attributes: [.posixPermissions: 0o600]
        )
    }

    func remove() {
        try? FileManager.default.removeItem(at: root)
    }

    private func write(_ data: Data, path: String) throws {
        let url = root.appending(path: path)
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        FileManager.default.createFile(
            atPath: url.path,
            contents: data,
            attributes: [.posixPermissions: 0o600]
        )
    }
}

private enum PLCFixture {
    static func makeGenesis(
        handle: String,
        signingPublicKey: P256.Signing.PublicKey
    ) throws -> PLCSignedOperation {
        let rotation = P256.Signing.PrivateKey()
        let unsigned = try PLCATProfile.regularOperation(
            handle: handle,
            signingPublicKey: signingPublicKey,
            rotationPublicKeys: [rotation.publicKey],
            pdsOrigin: URL(string: "https://pds.example.com")!,
            prev: nil
        )
        return try PLCOperationCodec.sign(.regular(unsigned), using: rotation)
    }

    static func historyJSON(
        operation: PLCSignedOperation,
        did: String,
        repositoryRevision: String,
        publicGenesisCommitCID: String
    ) throws -> Data {
        let operationObject = try JSONSerialization.jsonObject(with: operation.canonicalJSON)
        return try JSONSerialization.data(withJSONObject: [
            "format": "swan-plc-history-v1",
            "scope": "locally-retained-genesis",
            "did": did,
            "operationCID": try operation.cid.string,
            "operation": operationObject,
            "canonicalHandle": "alice.example.com",
            "pdsOrigin": "https://pds.example.com",
            "repositoryRevision": repositoryRevision,
            "publicGenesisCommitCID": publicGenesisCommitCID,
            "signingKeyBinding": "plc-atproto-current-v1",
        ], options: [.sortedKeys, .withoutEscapingSlashes])
    }
}

private let portableExportTestVerifier =
    "$argon2id$v=19$m=65536,t=3,p=1$bcdefghijklmnopqrstuvw$BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
