import Crypto
import Foundation
import Petrel
import SwanAccountExport
import SwanAccounts
import SwanPublicRepository
import SwanSpaces
import SwanSpacesWire
import XCTest

final class PortableRestoreCLITests: XCTestCase {
    func testOperatorAuthorityIsResolvedBeforeArchiveOrDataAccess() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let secretSentinel = "restore-secret-sentinel"
        let result = try runRestore(
            arguments: [
                "--data-directory", root.appending(path: "missing-data-sentinel").path,
                "--input-directory", root.appending(path: "missing-archive-sentinel").path,
                "--operator-secret-file", root.appending(path: "missing-secret").path,
            ],
            environment: [:]
        )

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.stdout.isEmpty)
        let diagnostic = String(decoding: result.stderr, as: UTF8.self)
        XCTAssertFalse(diagnostic.contains(root.path))
        XCTAssertFalse(diagnostic.contains("missing-data-sentinel"))
        XCTAssertFalse(diagnostic.contains("missing-archive-sentinel"))
        XCTAssertFalse(diagnostic.contains(secretSentinel))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), [])
    }

    func testSuccessPrintsExactSanitizedSortedJSONAndCreatesOnlyRestoreStaging() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let archive = try PortableRestoreCLIArchiveFixture(
            root: root.appending(path: "archive")
        )
        let dataDirectory = root.appending(path: "data")
        try FileManager.default.createDirectory(
            at: dataDirectory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let operatorSecret = root.appending(path: "operator-secret")
        let secret = Data("portable-restore-operator-secret-sentinel".utf8)
        try protectedWrite(secret, to: operatorSecret)

        let result = try runRestore(arguments: [
            "--data-directory", dataDirectory.path,
            "--input-directory", archive.root.path,
            "--operator-secret-file", operatorSecret.path,
        ])

        XCTAssertEqual(result.status, 0)
        XCTAssertTrue(result.stderr.isEmpty)
        let decoded = try JSONDecoder().decode(
            SwanPortableRestoreResult.self,
            from: result.stdout
        )
        XCTAssertEqual(decoded.status, .staged)
        XCTAssertEqual(decoded.did, archive.did)
        XCTAssertEqual(decoded.canonicalHandle, "alice.example.com")
        XCTAssertEqual(decoded.fileCount, 3)
        XCTAssertFalse(decoded.includesPrivateKeys)
        XCTAssertEqual(decoded.profileID, PermissionedData0016.profileID)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        XCTAssertEqual(result.stdout, try encoder.encode(decoded) + Data("\n".utf8))
        XCTAssertNil(result.stdout.range(of: secret))
        XCTAssertNil(result.stderr.range(of: secret))
        XCTAssertEqual(
            Set(try FileManager.default.contentsOfDirectory(atPath: dataDirectory.path)),
            ["restore-staging"]
        )
        for forbidden in ["control.sqlite", "actors", "keys", "oauth", "sessions"] {
            XCTAssertFalse(FileManager.default.fileExists(
                atPath: dataDirectory.appending(path: forbidden).path
            ))
        }
        let stagedURL = URL(fileURLWithPath: decoded.stagingDirectory)
        let verification = try SwanPortableExportVerifier.verifyArchive(at: stagedURL)
        XCTAssertEqual(verification.manifestSHA256, decoded.manifestSHA256)
    }

    func testArchiveFailureIsSanitizedAndDoesNotPersistSecretOrRestoreState() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let archive = root.appending(path: "bad-archive-payload-sentinel")
        let dataDirectory = root.appending(path: "data")
        for directory in [archive, dataDirectory] {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
        }
        let operatorSecret = root.appending(path: "operator-secret")
        let secret = Data("restore-failure-secret-sentinel".utf8)
        try protectedWrite(secret, to: operatorSecret)

        let result = try runRestore(arguments: [
            "--data-directory", dataDirectory.path,
            "--input-directory", archive.path,
            "--operator-secret-file", operatorSecret.path,
        ])

        XCTAssertNotEqual(result.status, 0)
        XCTAssertTrue(result.stdout.isEmpty)
        let diagnostic = String(decoding: result.stderr, as: UTF8.self)
        XCTAssertTrue(diagnostic.contains("portable restore failed"))
        XCTAssertFalse(diagnostic.contains(root.path))
        XCTAssertFalse(diagnostic.contains("bad-archive-payload-sentinel"))
        XCTAssertNil(result.stderr.range(of: secret))
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: dataDirectory.appending(path: "restore-staging").path
        ))
    }

    private func runRestore(
        arguments: [String],
        environment: [String: String] = [:]
    ) throws -> (status: Int32, stdout: Data, stderr: Data) {
        let process = Process()
        process.executableURL = try XCTUnwrap(executableURL())
        process.arguments = ["restore"] + arguments
        process.environment = environment
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
            .appending(path: "SwanPortableRestoreCLI-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }

    private func protectedWrite(_ data: Data, to url: URL) throws {
        try data.write(to: url)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: url.path
        )
    }

    private func executableURL() -> URL? {
        if let override = ProcessInfo.processInfo.environment["SWAN_TEST_EXECUTABLE"],
           !override.isEmpty,
           FileManager.default.isExecutableFile(atPath: override) {
            return URL(filePath: override)
        }
        let packageRoot = URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        for candidate in [
            packageRoot.appending(path: ".build-task20/debug/swan"),
            packageRoot.appending(path: ".build/debug/swan"),
        ] where FileManager.default.isExecutableFile(atPath: candidate.path) {
            return candidate
        }
        return nil
    }
}

private struct PortableRestoreCLIArchiveFixture {
    let root: URL
    let did: String

    init(root: URL) throws {
        self.root = root
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let signingKey = P256.Signing.PrivateKey()
        let rotationKey = P256.Signing.PrivateKey()
        let unsigned = try PLCATProfile.regularOperation(
            handle: "alice.example.com",
            signingPublicKey: signingKey.publicKey,
            rotationPublicKeys: [rotationKey.publicKey],
            pdsOrigin: URL(string: "https://pds.example.com")!,
            prev: nil
        )
        let operation = try PLCOperationCodec.sign(.regular(unsigned), using: rotationKey)
        did = try PLCOperationCodec.genesisDID(for: operation)
        let publicGenesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: "3jzfcijpj2z2a",
            signingKey: signingKey
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
        let value = Data([0xa1, 0x61, 0x78, 0x01])
        let cid = CID.fromDAGCBOR(value).string
        var state = LtHash()
        state.add(element: "\(recordURI.collection)/\(recordURI.rkey)/\(cid)")
        let commit = try SpaceCommitCodec.createReaderEnvelope(
            space: space,
            author: did,
            rev: "3jzfcijpj2z2b",
            commitment: state.commitment,
            key: signingKey
        )
        let spaceCAR = try SpaceCARCodec.encode(
            commit: commit,
            records: [.init(uri: recordURI, value: value, cid: cid, revision: 1)]
        ).data
        let spacePath =
            "spaces/\(SwanPortableExportPath.encode(space.rawValue))/"
            + "\(SwanPortableExportPath.encode(did)).car"
        try write(spaceCAR, path: spacePath)

        let history = try JSONSerialization.data(withJSONObject: [
            "format": "swan-plc-history-v1",
            "scope": "locally-retained-genesis",
            "did": did,
            "operationCID": try operation.cid.string,
            "operation": try JSONSerialization.jsonObject(with: operation.canonicalJSON),
            "canonicalHandle": "alice.example.com",
            "pdsOrigin": "https://pds.example.com",
            "repositoryRevision": publicGenesis.revision,
            "publicGenesisCommitCID": publicGenesis.commitCID.string,
            "signingKeyBinding": "plc-atproto-current-v1",
        ], options: [.sortedKeys, .withoutEscapingSlashes])
        try write(history, path: "plc/history.json")

        let payloads: [(String, SwanPortableExportFileType, Data)] = [
            ("plc/history.json", .plcHistory, history),
            ("public/repository.car", .publicCAR, publicGenesis.car),
            (spacePath, .spaceCAR, spaceCAR),
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
        try write(
            SwanPortableExportManifestCodec.encode(manifest),
            path: "manifest.json"
        )
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
