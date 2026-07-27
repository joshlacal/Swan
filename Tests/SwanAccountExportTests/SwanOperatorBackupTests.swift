import Crypto
import Foundation
import Petrel
@testable import SwanAccountExport
import SwanAccounts
import SwanPublicRepository
import SwanSQLite
import SwanStorage
import XCTest

final class SwanOperatorBackupTests: XCTestCase {
    func testValidBackupContainsVerifiedPortableArchiveAndOnlyEncryptedSecrets() async throws {
        let fixture = try await OperatorBackupFixture()
        defer { fixture.remove() }

        let output = fixture.root.appending(path: "backup")
        let result = try await fixture.backup(to: output)
        let verification = try SwanOperatorAccountBackupVerifier.verifyBackup(
            at: output,
            using: fixture.backupKey
        )
        let portable = try SwanPortableExportVerifier.verifyArchive(
            at: output.appending(path: "portable")
        )

        XCTAssertEqual(result.did, fixture.account.did)
        XCTAssertEqual(result.backupManifestSHA256, verification.backupManifestSHA256)
        XCTAssertEqual(result.portableManifestSHA256, portable.manifestSHA256)
        XCTAssertEqual(verification.did, fixture.account.did)
        XCTAssertEqual(
            verification.publicGenesisCommitCID,
            fixture.account.publicGenesisCommitCID
        )
        XCTAssertTrue(result.containsEncryptedPrivateKeys)
        let files = Set(try regularFiles(under: output))
        XCTAssertTrue(files.isSuperset(of: [
            "manifest.json",
            "operator/secrets.aesgcm",
            "portable/manifest.json",
            "portable/plc/history.json",
            "portable/public/repository.car",
        ]))
        XCTAssertEqual(files.filter { $0.hasPrefix("portable/blobs/public/") }.count, 1)

        let bytes = try allRegularFileBytes(under: output)
        for sentinel in fixture.secretSentinels {
            XCTAssertNil(bytes.range(of: sentinel))
        }
    }

    func testWrongKeyCiphertextAndAADBoundDigestRejectSafely() async throws {
        let fixture = try await OperatorBackupFixture()
        defer { fixture.remove() }
        let output = fixture.root.appending(path: "backup")
        _ = try await fixture.backup(to: output)

        XCTAssertThrowsError(
            try SwanOperatorAccountBackupVerifier.verifyBackup(
                at: output,
                using: try SwanOperatorBackupKey(rawBytes: Data(repeating: 0x91, count: 32))
            )
        ) { XCTAssertEqual($0 as? SwanOperatorAccountBackupError, .failed) }

        let envelopeURL = output.appending(path: "operator/secrets.aesgcm")
        var envelope = try Data(contentsOf: envelopeURL)
        envelope[envelope.startIndex + 15] ^= 0x80
        try envelope.write(to: envelopeURL)
        try replaceEnvelopeDigest(envelope, in: output)
        XCTAssertThrowsError(
            try SwanOperatorAccountBackupVerifier.verifyBackup(
                at: output,
                using: fixture.backupKey
            )
        ) { XCTAssertEqual($0 as? SwanOperatorAccountBackupError, .failed) }
    }

    func testNoncanonicalManifestExtraAndSymlinkEntriesReject() async throws {
        let fixture = try await OperatorBackupFixture()
        defer { fixture.remove() }

        let noncanonical = fixture.root.appending(path: "noncanonical")
        _ = try await fixture.backup(to: noncanonical)
        let manifestURL = noncanonical.appending(path: "manifest.json")
        let canonical = try Data(contentsOf: manifestURL)
        try (Data(" ".utf8) + canonical).write(to: manifestURL)
        XCTAssertThrowsError(
            try SwanOperatorAccountBackupVerifier.verifyBackup(
                at: noncanonical,
                using: fixture.backupKey
            )
        )

        let extra = fixture.root.appending(path: "extra")
        _ = try await fixture.backup(to: extra)
        try protectedWrite(Data("unexpected".utf8), to: extra.appending(path: "extra"))
        XCTAssertThrowsError(
            try SwanOperatorAccountBackupVerifier.verifyBackup(
                at: extra,
                using: fixture.backupKey
            )
        )

        let symlink = fixture.root.appending(path: "symlink")
        _ = try await fixture.backup(to: symlink)
        try FileManager.default.createSymbolicLink(
            at: symlink.appending(path: "link"),
            withDestinationURL: symlink.appending(path: "manifest.json")
        )
        XCTAssertThrowsError(
            try SwanOperatorAccountBackupVerifier.verifyBackup(
                at: symlink,
                using: fixture.backupKey
            )
        )
    }

    func testChangedPortableCARBlobAndDigestRejectAtOuterBoundary() async throws {
        let fixture = try await OperatorBackupFixture()
        defer { fixture.remove() }
        let blobSource = try await fixture.completedBackup(named: "blob-source")
        let blobPath = try XCTUnwrap(
            regularFiles(under: blobSource).first {
                $0.hasPrefix("portable/blobs/public/")
            }
        )

        for (name, relativePath) in [
            ("car", "portable/public/repository.car"),
            ("blob", blobPath),
        ] {
            let output: URL
            if name == "blob" {
                output = fixture.root.appending(path: "blob-source")
            } else {
                output = try await fixture.completedBackup(named: "changed-\(name)")
            }
            let artifact = output.appending(path: relativePath)
            var bytes = try Data(contentsOf: artifact)
            bytes[bytes.startIndex] ^= 0x01
            try bytes.write(to: artifact)
            XCTAssertThrowsError(
                try SwanOperatorAccountBackupVerifier.verifyBackup(
                    at: output,
                    using: fixture.backupKey
                ),
                "changed \(name) must fail"
            )
        }

        let digest = try await fixture.completedBackup(named: "changed-digest")
        let manifestURL = digest.appending(path: "manifest.json")
        var manifest = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: manifestURL))
                as? [String: Any]
        )
        manifest["portableManifestSHA256"] =
            "sha256:\(String(repeating: "0", count: 64))"
        try JSONSerialization.data(
            withJSONObject: manifest,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ).write(to: manifestURL)
        XCTAssertThrowsError(
            try SwanOperatorAccountBackupVerifier.verifyBackup(
                at: digest,
                using: fixture.backupKey
            )
        )
    }

    func testSwappedSecretIdentityScalarAndNoncanonicalPlaintextReject() async throws {
        let fixture = try await OperatorBackupFixture()
        defer { fixture.remove() }

        for (name, mutate) in [
            ("did", { (object: inout [String: Any]) in
                object["did"] = "did:plc:abcdefghijklmnopqrstuvwx"
            }),
            ("scalar", { (object: inout [String: Any]) in
                object["signingPrivateScalar"] =
                    Data(repeating: 0x6A, count: 32).base64URLEncoded
            }),
            ("reference", { (object: inout [String: Any]) in
                var reference = object["rotationKeyReference"] as! [String: Any]
                reference["generation"] = 2
                reference["reference"] = "account-rotation:2"
                object["rotationKeyReference"] = reference
            }),
        ] as [(String, (inout [String: Any]) -> Void)] {
            let output = fixture.root.appending(path: "swapped-\(name)")
            _ = try await fixture.backup(to: output)
            try rewriteEnvelope(in: output, key: fixture.backupKey) { plaintext in
                var object = try XCTUnwrap(
                    JSONSerialization.jsonObject(with: plaintext) as? [String: Any]
                )
                mutate(&object)
                return try JSONSerialization.data(
                    withJSONObject: object,
                    options: [.sortedKeys, .withoutEscapingSlashes]
                )
            }
            XCTAssertThrowsError(
                try SwanOperatorAccountBackupVerifier.verifyBackup(
                    at: output,
                    using: fixture.backupKey
                ),
                "swapped \(name) must fail"
            )
        }

        let noncanonical = fixture.root.appending(path: "secret-noncanonical")
        _ = try await fixture.backup(to: noncanonical)
        try rewriteEnvelope(in: noncanonical, key: fixture.backupKey) {
            Data(" ".utf8) + $0
        }
        XCTAssertThrowsError(
            try SwanOperatorAccountBackupVerifier.verifyBackup(
                at: noncanonical,
                using: fixture.backupKey
            )
        )
    }

    func testOutputCollisionAndPostRenameFailureLeaveNoTaskArtifacts() async throws {
        let fixture = try await OperatorBackupFixture()
        defer { fixture.remove() }
        let collision = fixture.root.appending(path: "collision")
        try FileManager.default.createDirectory(
            at: collision,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let before = try treeSnapshot(fixture.root)
        await XCTAssertThrowsErrorAsync {
            _ = try await fixture.backup(to: collision)
        }
        XCTAssertEqual(try treeSnapshot(fixture.root), before)

        let failed = fixture.root.appending(path: "post-rename")
        let exporter = SwanOperatorAccountBackupExporter(
            database: fixture.database,
            keyReader: fixture.keyStore,
            now: { Date(timeIntervalSince1970: 1_700_000_000) },
            afterRenameBeforeParentSync: {
                throw SwanOperatorAccountBackupError.failed
            }
        )
        await XCTAssertThrowsErrorAsync {
            _ = try await exporter.backup(
                account: fixture.account,
                credential: fixture.credential,
                using: fixture.backupKey,
                to: failed
            )
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: failed.path))
        XCTAssertFalse(
            try FileManager.default.contentsOfDirectory(atPath: fixture.root.path)
                .contains { $0.hasPrefix(".swan-backup-") }
        )
    }

    func testMountedBackupKeyRequiresCanonicalOwnerOnlyRegularFile() throws {
        let root = try temporaryDirectory(prefix: "SwanOperatorBackupKey")
        defer { try? FileManager.default.removeItem(at: root) }
        let key = Data(repeating: 0xAB, count: 32)
        let valid = root.appending(path: "valid")
        try protectedWrite(Data((key.base64URLEncoded + "\n").utf8), to: valid)
        _ = try SwanOperatorBackupKey(secretFile: valid)

        let broad = root.appending(path: "broad")
        try Data(key.base64URLEncoded.utf8).write(to: broad)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644],
            ofItemAtPath: broad.path
        )
        XCTAssertThrowsError(try SwanOperatorBackupKey(secretFile: broad))

        let padded = root.appending(path: "padded")
        try protectedWrite(Data((key.base64EncodedString()).utf8), to: padded)
        XCTAssertThrowsError(try SwanOperatorBackupKey(secretFile: padded))

        let link = root.appending(path: "link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: valid)
        XCTAssertThrowsError(try SwanOperatorBackupKey(secretFile: link))
    }
}

private struct OperatorBackupFixture {
    let root: URL
    let database: SQLiteAccountDatabase
    let keyStore: FileAccountKeyStore
    let account: AccountControlAccount
    let credential: AccountControlCredential
    let backupKey: SwanOperatorBackupKey
    let secretSentinels: [Data]

    init() async throws {
        root = try temporaryDirectory(prefix: "SwanOperatorBackup")
        let handle = "alice.example.com"
        let signingKey = P256.Signing.PrivateKey()
        let rotationKey = P256.Signing.PrivateKey()
        let unsigned = try PLCATProfile.regularOperation(
            handle: handle,
            signingPublicKey: signingKey.publicKey,
            rotationPublicKeys: [rotationKey.publicKey],
            pdsOrigin: URL(string: "https://pds.example.com")!,
            prev: nil
        )
        let operation = try PLCOperationCodec.sign(.regular(unsigned), using: rotationKey)
        let did = try PLCOperationCodec.genesisDID(for: operation)
        let kek = Data(repeating: 0xA7, count: 32)
        keyStore = try FileAccountKeyStore(
            root: root.appending(path: "keys"),
            configuration: try AccountKeyEncryptionConfiguration(
                activeKeyID: "primary",
                activeKey: kek
            )
        )
        try await keyStore.createBatch([
            try AccountKeyMaterial(
                reference: AccountKeyReference(
                    accountDID: did,
                    purpose: .signing,
                    generation: 1
                ),
                key: signingKey.rawRepresentation
            ),
            try AccountKeyMaterial(
                reference: AccountKeyReference(
                    accountDID: did,
                    purpose: .rotation,
                    generation: 1
                ),
                key: rotationKey.rawRepresentation
            ),
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
        let signingReference = try AccountControlKeyReference(
            purpose: .signing,
            generation: 1
        )
        let rotationReference = try AccountControlKeyReference(
            purpose: .rotation,
            generation: 1
        )
        let journal = try PLCAccountPreparationJournal(
            requestID: "operator-backup-test",
            canonicalHandle: handle,
            pdsOrigin: "https://pds.example.com",
            repositoryRevision: genesis.revision,
            operation: try PLCAccountPreparationOperationFacts(
                signingDIDKey: XCTUnwrap(operation.regular?.verificationMethods["atproto"]),
                rotationDIDKey: XCTUnwrap(operation.regular?.rotationKeys.first),
                signature: XCTUnwrap(operation.regular?.signature)
            ),
            signingKey: signingReference,
            rotationKey: rotationReference,
            publicGenesisCommitCID: nil,
            stage: .keysStored
        )
        _ = try await database.installPLCAccountPreparationJournal(journal)
        _ = try await database.advancePLCAccountPreparationJournal(
            requestID: journal.requestID,
            expectedStage: .keysStored,
            to: .repositoryInstalled,
            publicGenesisCommitCID: genesis.commitCID.string
        )
        _ = try await database.advancePLCAccountPreparationJournal(
            requestID: journal.requestID,
            expectedStage: .repositoryInstalled,
            to: .submissionPending,
            publicGenesisCommitCID: nil
        )
        _ = try await database.putBlob(
            Data("operator-backup-public-blob".utf8),
            namespace: .public
        )
        _ = try await database.advancePLCAccountPreparationJournal(
            requestID: journal.requestID,
            expectedStage: .submissionPending,
            to: .submitted,
            publicGenesisCommitCID: nil
        )
        account = try AccountControlAccount(
            did: did,
            canonicalHandle: handle,
            status: .active,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            credentialState: .configured,
            signingKey: signingReference,
            rotationKey: rotationReference,
            publicGenesisCommitCID: genesis.commitCID.string
        )
        credential = try AccountControlCredential(
            did: did,
            verifier: operatorBackupVerifierSentinel,
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let rawBackupKey = Data(repeating: 0xC3, count: 32)
        backupKey = try SwanOperatorBackupKey(rawBytes: rawBackupKey)
        secretSentinels = [
            kek,
            rawBackupKey,
            signingKey.rawRepresentation,
            rotationKey.rawRepresentation,
            Data(operatorBackupVerifierSentinel.utf8),
        ]
    }

    func backup(to output: URL) async throws -> SwanOperatorAccountBackupResult {
        try await SwanOperatorAccountBackupExporter(
            database: database,
            keyReader: keyStore,
            now: { Date(timeIntervalSince1970: 1_700_000_000) }
        ).backup(
            account: account,
            credential: credential,
            using: backupKey,
            to: output
        )
    }

    func completedBackup(named name: String) async throws -> URL {
        let output = root.appending(path: name)
        _ = try await backup(to: output)
        return output
    }

    func remove() {
        Task { try? await database.close() }
        try? FileManager.default.removeItem(at: root)
    }
}

private func rewriteEnvelope(
    in root: URL,
    key: SwanOperatorBackupKey,
    transform: (Data) throws -> Data
) throws {
    let manifestURL = root.appending(path: "manifest.json")
    let object = try XCTUnwrap(
        JSONSerialization.jsonObject(with: Data(contentsOf: manifestURL)) as? [String: Any]
    )
    let portableDigest = try XCTUnwrap(object["portableManifestSHA256"] as? String)
    let envelopeURL = root.appending(path: "operator/secrets.aesgcm")
    let envelope = try Data(contentsOf: envelopeURL)
    let aad = Data(
        [
            "swan-operator-account-backup-v1",
            "permissioned-data-0016-2026-07-03",
            portableDigest,
        ].joined(separator: "\u{0}").utf8
    )
    let plaintext = try AES.GCM.open(
        AES.GCM.SealedBox(combined: envelope),
        using: SymmetricKey(data: key.bytes),
        authenticating: aad
    )
    let changed = try transform(plaintext)
    let sealed = try XCTUnwrap(
        AES.GCM.seal(
            changed,
            using: SymmetricKey(data: key.bytes),
            authenticating: aad
        ).combined
    )
    try sealed.write(to: envelopeURL)
    try replaceEnvelopeDigest(sealed, in: root)
}

private func replaceEnvelopeDigest(_ data: Data, in root: URL) throws {
    let manifestURL = root.appending(path: "manifest.json")
    var object = try XCTUnwrap(
        JSONSerialization.jsonObject(with: Data(contentsOf: manifestURL)) as? [String: Any]
    )
    object["envelopeSHA256"] = SwanPortableExportDigest.hex(data)
    try JSONSerialization.data(
        withJSONObject: object,
        options: [.sortedKeys, .withoutEscapingSlashes]
    ).write(to: manifestURL)
}

private func temporaryDirectory(prefix: String) throws -> URL {
    let root = FileManager.default.temporaryDirectory
        .appending(path: "\(prefix)-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
        at: root,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    return root
}

private func protectedWrite(_ data: Data, to url: URL) throws {
    FileManager.default.createFile(
        atPath: url.path,
        contents: data,
        attributes: [.posixPermissions: 0o600]
    )
}

private func regularFiles(under root: URL) throws -> [String] {
    let canonicalRoot = root.resolvingSymlinksInPath().path
    let enumerator = try XCTUnwrap(
        FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [],
            errorHandler: nil
        )
    )
    var paths: [String] = []
    for case let url as URL in enumerator
    where try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true {
        let canonicalPath = url.resolvingSymlinksInPath().path
        paths.append(String(canonicalPath.dropFirst(canonicalRoot.count + 1)))
    }
    return paths.sorted()
}

private func allRegularFileBytes(under root: URL) throws -> Data {
    try regularFiles(under: root).reduce(into: Data()) {
        $0.append(try Data(contentsOf: root.appending(path: $1)))
    }
}

private func treeSnapshot(_ root: URL) throws -> [String: Data] {
    let enumerator = try XCTUnwrap(
        FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey],
            options: [],
            errorHandler: nil
        )
    )
    var result: [String: Data] = [:]
    for case let url as URL in enumerator {
        let relative = String(url.path.dropFirst(root.path.count + 1))
        let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey])
        let mode = (try FileManager.default.attributesOfItem(
            atPath: url.path
        )[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        if values.isDirectory == true {
            result[relative] = Data("directory:\(mode)".utf8)
        } else if values.isRegularFile == true {
            result[relative] = Data("file:\(mode):".utf8)
                + (try Data(contentsOf: url))
        }
    }
    return result
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

private extension Data {
    var base64URLEncoded: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private let operatorBackupVerifierSentinel =
    "$argon2id$v=19$m=65536,t=3,p=1$bcdefghijklmnopqrstuvw$BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
