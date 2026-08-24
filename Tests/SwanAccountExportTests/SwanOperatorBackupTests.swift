import Crypto
import Foundation
import Petrel
import PetrelCrypto
import PetrelPLC
@testable import SwanAccountExport
import SwanAccounts
import PetrelRepo
@_spi(PortableRestore) import SwanSQLite
import SwanSpaces
import SwanStorage
import XCTest

final class SwanOperatorBackupTests: XCTestCase {
    func testPreoccupiedCleanupQuarantineBlocksStagingAndPreservesSentinel()
        async throws
    {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
        XCTAssertThrowsError(
            try SwanPortableExportDestination(
                fixture.root.appending(
                    path: SwanPortableExportFilesystem.cleanupQuarantineName
                )
            )
        )
        await XCTAssertThrowsErrorAsync {
            _ = try await fixture.backup(
                to: fixture.root.appending(
                    path: SwanPortableExportFilesystem.cleanupQuarantineName
                )
            )
        }
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: fixture.root.appending(
                    path: SwanPortableExportFilesystem.cleanupQuarantineName
                ).path
            )
        )
        let quarantine = fixture.root.appending(
            path: SwanPortableExportFilesystem.cleanupQuarantineName
        )
        try FileManager.default.createDirectory(
            at: quarantine,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let sentinel = Data("operator-owned-quarantine".utf8)
        try protectedWrite(sentinel, to: quarantine.appending(path: "sentinel"))

        await XCTAssertThrowsErrorAsync {
            _ = try await fixture.backup(
                to: fixture.root.appending(path: "blocked-backup")
            )
        }

        XCTAssertEqual(
            try Data(contentsOf: quarantine.appending(path: "sentinel")),
            sentinel
        )
        XCTAssertFalse(
            try FileManager.default.contentsOfDirectory(atPath: fixture.root.path)
                .contains { $0.hasPrefix(".swan-backup-") }
        )
    }

    func testConcurrentStagingForOneParentAdmitsOnlyOneOperation() async throws {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let firstExporter = SwanOperatorAccountBackupExporter(
            database: fixture.database,
            keyReader: fixture.keyStore,
            continuityInventory: {
                try PLCCredentialKeyContinuityInventory(checkpoints: [])
            },
            afterRenameBeforeParentSync: {
                entered.signal()
                guard release.wait(timeout: .now() + 5) == .success else {
                    throw SwanOperatorAccountBackupError.failed
                }
            }
        )
        let first = Task {
            try await firstExporter.backup(
                account: fixture.account,
                credential: fixture.credential,
                using: fixture.backupKey,
                to: fixture.root.appending(path: "concurrent-first")
            )
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)

        await XCTAssertThrowsErrorAsync {
            _ = try await fixture.backup(
                to: fixture.root.appending(path: "concurrent-second")
            )
        }
        release.signal()
        _ = try await first.value
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: fixture.root.appending(path: "concurrent-second").path
            )
        )
    }

    func testValidBackupContainsVerifiedPortableArchiveAndOnlyEncryptedSecrets() async throws {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }

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
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
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
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }

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
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
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
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }

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
            ("both-references-generation", { (object: inout [String: Any]) in
                var signing = object["signingKeyReference"] as! [String: Any]
                signing["generation"] = 2
                signing["reference"] = "account-signing:2"
                object["signingKeyReference"] = signing
                var rotation = object["rotationKeyReference"] as! [String: Any]
                rotation["generation"] = 2
                rotation["reference"] = "account-rotation:2"
                object["rotationKeyReference"] = rotation
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
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
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
            continuityInventory: {
                try PLCCredentialKeyContinuityInventory(checkpoints: [])
            },
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
        XCTAssertFalse(
            try FileManager.default.contentsOfDirectory(atPath: fixture.root.path)
                .contains { $0.hasPrefix(".swan-scrubbed-restore-") }
        )
        let quarantine = fixture.root.appending(
            path: SwanPortableExportFilesystem.cleanupQuarantineName
        )
        XCTAssertTrue(FileManager.default.fileExists(atPath: quarantine.path))
        XCTAssertTrue(try allRegularFileBytes(under: quarantine).isEmpty)
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

final class SwanOperatorAccountRestoreTests: XCTestCase {
    func testRestoreRejectsArchiveWideLogicalRepositoryAmplification()
        async throws
    {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
        let secondRecordByteCount = try await fixture.addSecondRepository()
        let backup = try await fixture.completedBackup(named: "aggregate-source")
        let portable = try await SwanPortableExportVerifier.verifyArchiveStreaming(
            at: backup.appending(path: "portable")
        )
        XCTAssertEqual(
            portable.manifest.files.filter { $0.type == .spaceCAR }.count,
            2
        )
        let failedParent = fixture.root.appending(path: "aggregate-failed-parent")
        let successParent = fixture.root.appending(path: "aggregate-success-parent")
        for parent in [failedParent, successParent] {
            try FileManager.default.createDirectory(
                at: parent,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
        }
        let target = failedParent.appending(path: "data")
        let restoredKEK = try SwanOperatorAccountKEK(
            rawBytes: Data(repeating: 0xD4, count: 32)
        )
        let individuallyValidAggregate =
            fixture.initialRecordByteCount + secondRecordByteCount
        let bounded = SwanOperatorAccountRestorer(
            maximumLogicalRestoredBytes: individuallyValidAggregate - 1
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await bounded.restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: restoredKEK,
                to: target
            )
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))

        _ = try await SwanOperatorAccountRestorer().restore(
            backupAt: backup,
            using: fixture.backupKey,
            accountKEK: restoredKEK,
            to: successParent.appending(path: "data")
        )
    }

    func testVerifiedBackupRestoresOneActiveAccountAndReopensEveryDurableBoundary() async throws {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
        let backup = try await fixture.completedBackup(named: "restore-source")
        let sourceBefore = try treeSnapshot(backup)
        let sourceEnvelopePlaintext = try decryptedEnvelope(
            in: backup,
            key: fixture.backupKey
        )
        let target = fixture.root.appending(path: "restored-data")
        let restoredKEK = try SwanOperatorAccountKEK(
            rawBytes: Data(repeating: 0xD4, count: 32)
        )

        let result = try await SwanOperatorAccountRestorer().restore(
            backupAt: backup,
            using: fixture.backupKey,
            accountKEK: restoredKEK,
            accountKEKID: "primary",
            to: target
        )
        XCTAssertEqual(try treeSnapshot(backup), sourceBefore)

        XCTAssertEqual(result.status, "restored")
        XCTAssertEqual(result.did, fixture.account.did)
        XCTAssertEqual(result.canonicalHandle, fixture.account.canonicalHandle)
        XCTAssertEqual(
            result.publicGenesisCommitCID,
            fixture.account.publicGenesisCommitCID
        )
        XCTAssertEqual(result.targetDataDirectory, target.standardizedFileURL.path)

        let control = try await SQLiteControlDatabase(dataDirectory: target)
        let loadedAccount = try await control.account(did: fixture.account.did)
        let account = try XCTUnwrap(loadedAccount)
        XCTAssertEqual(account.status, .active)
        XCTAssertEqual(account.publicGenesisCommitCID, fixture.account.publicGenesisCommitCID)
        let activeDIDs = try await control.activeAccountDIDs()
        XCTAssertEqual(activeDIDs, [fixture.account.did])
        let loadedCredential = try await control.credential(did: fixture.account.did)
        let credential = try XCTUnwrap(loadedCredential)
        XCTAssertEqual(credential.verifier, fixture.credential.verifier)
        XCTAssertTrue(
            try LibsodiumArgon2idHasher().verify(
                fixture.password,
                encodedHash: credential.verifier
            )
        )
        try await control.close()

        let keyStore = try FileAccountKeyStore(
            root: target.appending(path: "keys"),
            configuration: try AccountKeyEncryptionConfiguration(
                activeKeyID: "primary",
                activeKey: restoredKEK.bytes
            )
        )
        let signingReference = try AccountKeyReference(
            accountDID: fixture.account.did,
            purpose: .signing,
            generation: 1
        )
        let restoredSigningKey = try P256.Signing.PrivateKey(
            rawRepresentation: await keyStore.key(for: signingReference)
        )
        let sourceSigningPublicKey = try P256.Signing.PrivateKey(
            rawRepresentation: await fixture.keyStore.key(for: signingReference)
        )
        XCTAssertEqual(
            restoredSigningKey.publicKey.compressedRepresentation,
            sourceSigningPublicKey.publicKey.compressedRepresentation
        )
        let rotationReference = try AccountKeyReference(
            accountDID: fixture.account.did,
            purpose: .rotation,
            generation: 1
        )
        let restoredRotationKey = try P256.Signing.PrivateKey(
            rawRepresentation: await keyStore.key(for: rotationReference)
        )
        let sourceRotationPublicKey = try P256.Signing.PrivateKey(
            rawRepresentation: await fixture.keyStore.key(for: rotationReference)
        )
        XCTAssertEqual(
            restoredRotationKey.publicKey.compressedRepresentation,
            sourceRotationPublicKey.publicKey.compressedRepresentation
        )
        let wrongKeyReader = try ExistingFileAccountKeyReader(
            root: target.appending(path: "keys"),
            configuration: try AccountKeyEncryptionConfiguration(
                activeKeyID: "primary",
                activeKey: Data(repeating: 0xD5, count: 32)
            )
        )
        await XCTAssertThrowsErrorAsync {
            _ = try await wrongKeyReader.key(for: signingReference)
        }

        let database = try await SQLiteAccountDatabase(dataDirectory: target, did: fixture.account.did)
        let loadedGenesis = try await database.loadPublicRepositoryGenesis(
            did: fixture.account.did,
            signingPublicKey: restoredSigningKey.publicKey
        )
        let genesis = try XCTUnwrap(loadedGenesis)
        XCTAssertEqual(genesis.genesis.commitCID.string, fixture.account.publicGenesisCommitCID)
        let restoredInventory = try await database.portableExportInventory()
        let sourceInventory = try await fixture.database.portableExportInventory()
        XCTAssertEqual(restoredInventory, sourceInventory)
        let portable = try SwanPortableExportVerifier.verifyArchive(
            at: backup.appending(path: "portable")
        )
        let spaceEntry = try XCTUnwrap(
            portable.manifest.files.first { $0.type == .spaceCAR }
        )
        let recovery = try SpaceCARCodec.verifyRecovery(
            Data(
                contentsOf: backup
                    .appending(path: "portable")
                    .appending(path: spaceEntry.path)
            ),
            space: fixture.space,
            author: fixture.account.did,
            publicKey: portable.signingPublicKey
        )
        try await database.validatePortableRestore(
            repositories: [
                SQLitePortableRestoreRepository(
                    space: fixture.space,
                    author: fixture.account.did,
                    recovery: recovery
                ),
            ]
        )
        let restoredPublicBlob = try XCTUnwrap(
            restoredInventory.blobs.first {
                if case .public = $0.namespace { return true }
                return false
            }
        )
        let restoredPublicBlobData = try await database.publicData(
            cid: restoredPublicBlob.cid
        )
        XCTAssertNotNil(restoredPublicBlobData)
        await XCTAssertThrowsErrorAsync {
            _ = try await database.repositoryState(
                space: fixture.space,
                author: fixture.account.did
            )
        }
        let restoredSpaceBlob = try XCTUnwrap(
            restoredInventory.blobs.first {
                if case .space(fixture.space) = $0.namespace { return true }
                return false
            }
        )
        await XCTAssertThrowsErrorAsync {
            _ = try await database.permissionedBlob(
                space: fixture.space,
                author: fixture.account.did,
                cid: restoredSpaceBlob.cid
            )
        }
        try await database.close()

        let bootstrapControl = try await SQLiteControlDatabase(dataDirectory: target)
        addTeardownBlock { try? await bootstrapControl.close() }
        let restoredDirectory = try await SQLitePreMigratedAccountDirectory.bootstrap(
            dataDirectory: target,
            controlStore: bootstrapControl,
            publicIdentityVerifier: SwanPublicPLCGenesisVerifier()
        )
        let restoredDescription = try await restoredDirectory.describePublicRepository(
            selector: fixture.account.did
        )
        XCTAssertNotNil(restoredDescription)
        try await restoredDirectory.close()
        try await bootstrapControl.close()

        let targetBytes = try allRegularFileBytes(under: target)
        for sentinel in fixture.secretSentinels.prefix(4) {
            XCTAssertNil(targetBytes.range(of: sentinel))
        }
        XCTAssertNil(targetBytes.range(of: restoredKEK.bytes))
        XCTAssertNil(targetBytes.range(of: sourceEnvelopePlaintext))
    }

    func testSourceFailureAndDestinationCollisionNeverCreateOrMergeTarget() async throws {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
        XCTAssertThrowsError(
            try SwanOperatorAccountKEK(rawBytes: Data(repeating: 0xD4, count: 31))
        )
        let backup = try await fixture.completedBackup(named: "failure-source")
        let target = fixture.root.appending(path: "must-remain-absent")
        let accountKEK = try SwanOperatorAccountKEK(
            rawBytes: Data(repeating: 0xD4, count: 32)
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await SwanOperatorAccountRestorer().restore(
                backupAt: backup,
                using: try SwanOperatorBackupKey(
                    rawBytes: Data(repeating: 0x91, count: 32)
                ),
                accountKEK: accountKEK,
                to: target
            )
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
        XCTAssertFalse(
            try FileManager.default.contentsOfDirectory(atPath: fixture.root.path)
                .contains { $0.hasPrefix(".swan-account-restore-") }
        )

        let carURL = backup.appending(path: "portable/public/repository.car")
        var car = try Data(contentsOf: carURL)
        car[car.startIndex] ^= 0x01
        try car.write(to: carURL)
        let alteredTarget = fixture.root.appending(path: "altered-must-remain-absent")
        await XCTAssertThrowsErrorAsync {
            _ = try await SwanOperatorAccountRestorer().restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: alteredTarget
            )
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: alteredTarget.path))

        let validBackup = try await fixture.completedBackup(named: "collision-source")
        try FileManager.default.createDirectory(
            at: target,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try protectedWrite(Data("do-not-merge".utf8), to: target.appending(path: "sentinel"))
        let before = try treeSnapshot(target)
        await XCTAssertThrowsErrorAsync {
            _ = try await SwanOperatorAccountRestorer().restore(
                backupAt: validBackup,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: target
            )
        }
        XCTAssertEqual(try treeSnapshot(target), before)
    }

    func testPrepublicationParentReplacementAndPostRenameFailureCleanlyRetry() async throws {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
        let backup = try await fixture.completedBackup(named: "atomic-source")
        let accountKEK = try SwanOperatorAccountKEK(
            rawBytes: Data(repeating: 0xD4, count: 32)
        )

        let parent = fixture.root.appending(path: "restore-parent")
        let displaced = fixture.root.appending(path: "restore-parent-displaced")
        try FileManager.default.createDirectory(
            at: parent,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let replacedTarget = parent.appending(path: "data")
        let replacing = SwanOperatorAccountRestorer(
            afterStagingBeforeValidation: {
                try FileManager.default.moveItem(at: parent, to: displaced)
                try FileManager.default.createDirectory(
                    at: parent,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700]
                )
            }
        )
        await XCTAssertThrowsErrorAsync {
            _ = try await replacing.restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: replacedTarget
            )
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: replacedTarget.path))
        XCTAssertFalse(
            try FileManager.default.contentsOfDirectory(atPath: displaced.path)
                .contains { $0.hasPrefix(".swan-account-restore-") }
        )
        try FileManager.default.removeItem(at: displaced)
        _ = try await SwanOperatorAccountRestorer().restore(
            backupAt: backup,
            using: fixture.backupKey,
            accountKEK: accountKEK,
            to: replacedTarget
        )

        let postRenameTarget = fixture.root.appending(path: "post-rename-data")
        let interrupted = SwanOperatorAccountRestorer(
            afterRenameBeforeParentSync: {
                throw SwanOperatorAccountRestoreError.failed
            }
        )
        await XCTAssertThrowsErrorAsync {
            _ = try await interrupted.restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: postRenameTarget
            )
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: postRenameTarget.path))
        await XCTAssertThrowsErrorAsync {
            _ = try await SwanOperatorAccountRestorer().restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: postRenameTarget
            )
        }
    }

    func testPostInstallRecordValueMutationPreservingCIDFailsBeforePublication()
        async throws
    {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
        let backup = try await fixture.completedBackup(named: "record-mutation-source")
        let target = fixture.root.appending(path: "record-mutation-target")
        let mutatedValue = try DAGCBOR.encodeValue(
            OrderedCBORMap(entries: [(key: "text", value: "restore no")])
        )
        XCTAssertEqual(mutatedValue.count, fixture.initialRecordValue.count)
        XCTAssertNotEqual(
            CID.fromDAGCBOR(mutatedValue),
            CID.fromDAGCBOR(fixture.initialRecordValue)
        )
        let mutationRan = UnsafeSendableBox(false)
        let restorer = SwanOperatorAccountRestorer(
            afterStagingBeforeValidation: {
                let stageName = try XCTUnwrap(
                    FileManager.default.contentsOfDirectory(atPath: fixture.root.path)
                        .first { $0.hasPrefix(".swan-account-restore-") }
                )
                let stage = fixture.root.appending(path: stageName)
                let databaseURL = SQLiteLayout.accountDatabase(
                    in: stage,
                    did: fixture.account.did
                )
                try replaceFirstOccurrenceInPlace(
                    fixture.initialRecordValue,
                    with: mutatedValue,
                    in: databaseURL
                )
                mutationRan.value = true
            }
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await restorer.restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: try SwanOperatorAccountKEK(
                    rawBytes: Data(repeating: 0xD4, count: 32)
                ),
                to: target
            )
        }

        XCTAssertTrue(mutationRan.value)
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
        XCTAssertFalse(
            try FileManager.default.contentsOfDirectory(atPath: fixture.root.path)
                .contains { $0.hasPrefix(".swan-account-restore-") }
        )
    }

    func testPostRenameRecordMutationFailsInstalledRevalidation() async throws {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
        let backup = try await fixture.completedBackup(named: "post-rename-record-source")
        let target = fixture.root.appending(path: "post-rename-record-target")
        let mutatedValue = try DAGCBOR.encodeValue(
            OrderedCBORMap(entries: [(key: "text", value: "restore no")])
        )
        XCTAssertEqual(mutatedValue.count, fixture.initialRecordValue.count)
        let mutationRan = UnsafeSendableBox(false)
        let restorer = SwanOperatorAccountRestorer(
            afterRenameBeforeParentSync: {
                try replaceFirstOccurrenceInPlace(
                    fixture.initialRecordValue,
                    with: mutatedValue,
                    in: SQLiteLayout.accountDatabase(
                        in: target,
                        did: fixture.account.did
                    )
                )
                mutationRan.value = true
            }
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await restorer.restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: try SwanOperatorAccountKEK(
                    rawBytes: Data(repeating: 0xD4, count: 32)
                ),
                to: target
            )
        }
        XCTAssertTrue(mutationRan.value)
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
    }

    func testStageReplacementBeforeInstallCannotRedirectWritesAndCleanupFindsPinnedInode()
        async throws
    {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
        let backup = try await fixture.completedBackup(named: "replacement-source")
        let accountKEK = try SwanOperatorAccountKEK(
            rawBytes: Data(repeating: 0xD4, count: 32)
        )
        let parent = fixture.root.appending(path: "replacement-parent")
        try FileManager.default.createDirectory(
            at: parent,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let target = parent.appending(path: "data")
        let displaced = parent.appending(path: "displaced-pinned-stage")
        let replacementSentinel = Data("replacement-owned".utf8)
        let originalName = UnsafeSendableBox<String?>(nil)
        let replacing = SwanOperatorAccountRestorer(
            afterStagingBeforeInstall: {
                let name = try XCTUnwrap(
                    FileManager.default.contentsOfDirectory(atPath: parent.path)
                        .first { $0.hasPrefix(".swan-account-restore-") }
                )
                originalName.value = name
                try FileManager.default.moveItem(
                    at: parent.appending(path: name),
                    to: displaced
                )
                let replacement = parent.appending(path: name)
                try FileManager.default.createDirectory(
                    at: replacement,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700]
                )
                try protectedWrite(
                    replacementSentinel,
                    to: replacement.appending(path: "sentinel")
                )
            }
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await replacing.restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: target
            )
        }

        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: displaced.path))
        let replacement = parent.appending(
            path: try XCTUnwrap(originalName.value)
        )
        XCTAssertEqual(
            try Data(contentsOf: replacement.appending(path: "sentinel")),
            replacementSentinel
        )
        XCTAssertEqual(
            try FileManager.default.contentsOfDirectory(atPath: replacement.path),
            ["sentinel"]
        )
        try FileManager.default.removeItem(at: replacement)
        await XCTAssertThrowsErrorAsync {
            _ = try await SwanOperatorAccountRestorer().restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: target
            )
        }
    }

    func testSwapAfterPathValidationCannotRedirectKeyOrSQLiteWrites() async throws {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
        let backup = try await fixture.completedBackup(named: "post-check-source")
        let accountKEK = try SwanOperatorAccountKEK(
            rawBytes: Data(repeating: 0xD4, count: 32)
        )
        let parent = fixture.root.appending(path: "post-check-parent")
        try FileManager.default.createDirectory(
            at: parent,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let target = parent.appending(path: "data")
        let displaced = parent.appending(path: "post-check-pinned-stage")
        let replacementSentinel = Data("post-check-replacement".utf8)
        let originalName = UnsafeSendableBox<String?>(nil)
        let replacing = SwanOperatorAccountRestorer(
            afterStagingPathValidatedBeforeStorageOpen: {
                let name = try XCTUnwrap(
                    FileManager.default.contentsOfDirectory(atPath: parent.path)
                        .first { $0.hasPrefix(".swan-account-restore-") }
                )
                originalName.value = name
                try FileManager.default.moveItem(
                    at: parent.appending(path: name),
                    to: displaced
                )
                let replacement = parent.appending(path: name)
                try FileManager.default.createDirectory(
                    at: replacement,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700]
                )
                try protectedWrite(
                    replacementSentinel,
                    to: replacement.appending(path: "sentinel")
                )
            }
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await replacing.restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: target
            )
        }

        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
        let replacement = parent.appending(path: try XCTUnwrap(originalName.value))
        XCTAssertEqual(
            try FileManager.default.contentsOfDirectory(atPath: replacement.path),
            ["sentinel"]
        )
        XCTAssertEqual(
            try Data(contentsOf: replacement.appending(path: "sentinel")),
            replacementSentinel
        )
        if FileManager.default.fileExists(atPath: displaced.path) {
            XCTAssertTrue(try allRegularFileBytes(under: displaced).isEmpty)
        }

        await XCTAssertThrowsErrorAsync {
            _ = try await SwanOperatorAccountRestorer().restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: target
            )
        }
    }

    func testCleanupEntrySwapNeverDeletesReplacementOrLeavesSecretState() async throws {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
        let backup = try await fixture.completedBackup(named: "cleanup-swap-source")
        let accountKEK = try SwanOperatorAccountKEK(
            rawBytes: Data(repeating: 0xD4, count: 32)
        )
        let parent = fixture.root.appending(path: "cleanup-swap-parent")
        try FileManager.default.createDirectory(
            at: parent,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let target = parent.appending(path: "data")
        let displaced = parent.appending(path: "cleanup-swap-pinned-stage")
        let replacementSentinel = Data("cleanup-replacement".utf8)
        let originalName = UnsafeSendableBox<String?>(nil)
        let interrupted = SwanOperatorAccountRestorer(
            afterStagingBeforeValidation: {
                throw SwanOperatorAccountRestoreError.failed
            },
            afterCleanupEntryResolvedBeforeRemoval: { name in
                originalName.value = name
                try FileManager.default.moveItem(
                    at: parent.appending(path: name),
                    to: displaced
                )
                let replacement = parent.appending(path: name)
                try FileManager.default.createDirectory(
                    at: replacement,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700]
                )
                try protectedWrite(
                    replacementSentinel,
                    to: replacement.appending(path: "sentinel")
                )
            }
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await interrupted.restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: target
            )
        }

        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
        let replacement = parent.appending(path: try XCTUnwrap(originalName.value))
        XCTAssertFalse(FileManager.default.fileExists(atPath: replacement.path))
        let quarantine = parent.appending(
            path: SwanPortableExportFilesystem.cleanupQuarantineName
        ).appending(
            path: SwanPortableExportFilesystem.cleanupQuarantinedTreeName
        )
        XCTAssertEqual(
            try Data(contentsOf: quarantine.appending(path: "sentinel")),
            replacementSentinel
        )
        XCTAssertTrue(FileManager.default.fileExists(atPath: displaced.path))
        XCTAssertTrue(try allRegularFileBytes(under: displaced).isEmpty)
        XCTAssertFalse(
            try FileManager.default.contentsOfDirectory(atPath: parent.path)
                .contains { $0.hasPrefix(".swan-scrubbed-restore-") }
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await SwanOperatorAccountRestorer().restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: target
            )
        }
    }

    func testQuarantineTreeSwapAfterMovePreservesReplacementAndBlocksParent()
        async throws
    {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
        let backup = try await fixture.completedBackup(named: "quarantine-swap-source")
        let accountKEK = try SwanOperatorAccountKEK(
            rawBytes: Data(repeating: 0xD4, count: 32)
        )
        let parent = fixture.root.appending(path: "quarantine-swap-parent")
        try FileManager.default.createDirectory(
            at: parent,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let target = parent.appending(path: "data")
        let quarantine = parent.appending(
            path: SwanPortableExportFilesystem.cleanupQuarantineName
        )
        let tree = quarantine.appending(
            path: SwanPortableExportFilesystem.cleanupQuarantinedTreeName
        )
        let displaced = quarantine.appending(path: "displaced-pinned-tree")
        let sentinel = Data("quarantine-replacement".utf8)
        let interrupted = SwanOperatorAccountRestorer(
            afterStagingBeforeValidation: {
                throw SwanOperatorAccountRestoreError.failed
            },
            afterQuarantineMoveBeforeValidation: {
                try FileManager.default.moveItem(at: tree, to: displaced)
                try FileManager.default.createDirectory(
                    at: tree,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700]
                )
                try protectedWrite(sentinel, to: tree.appending(path: "sentinel"))
            }
        )

        await XCTAssertThrowsErrorAsync {
            _ = try await interrupted.restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: target
            )
        }

        XCTAssertEqual(
            try Data(contentsOf: tree.appending(path: "sentinel")),
            sentinel
        )
        XCTAssertTrue(try allRegularFileBytes(under: displaced).isEmpty)
        await XCTAssertThrowsErrorAsync {
            _ = try await SwanOperatorAccountRestorer().restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: target
            )
        }
    }

    func testDestinationInsideSourceIsRejectedWithoutMutatingSource() async throws {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
        let backup = try await fixture.completedBackup(named: "overlap-source")
        let sourceBefore = try treeSnapshot(backup)
        let target = backup.appending(path: "restored-data")

        await XCTAssertThrowsErrorAsync {
            _ = try await SwanOperatorAccountRestorer().restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: try SwanOperatorAccountKEK(
                    rawBytes: Data(repeating: 0xD4, count: 32)
                ),
                to: target
            )
        }

        XCTAssertEqual(try treeSnapshot(backup), sourceBefore)
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
        XCTAssertFalse(
            try FileManager.default.contentsOfDirectory(atPath: backup.path)
                .contains { $0.hasPrefix(".swan-account-restore-") }
        )
    }

    func testAuthenticatedSourceMutationMatrixFailsBeforeDestinationAndCanRetry()
        async throws
    {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
        let accountKEK = try SwanOperatorAccountKEK(
            rawBytes: Data(repeating: 0xD4, count: 32)
        )
        let mutations: [(String, (URL) throws -> Void)] = [
            ("outer-manifest", { root in
                let url = root.appending(path: "manifest.json")
                try (Data(" ".utf8) + Data(contentsOf: url)).write(to: url)
            }),
            ("inner-manifest", { root in
                let url = root.appending(path: "portable/manifest.json")
                try (Data(" ".utf8) + Data(contentsOf: url)).write(to: url)
            }),
            ("envelope", { root in
                try flipFirstByte(
                    at: root.appending(path: "operator/secrets.aesgcm")
                )
            }),
            ("plc", { root in
                try flipFirstByte(
                    at: root.appending(path: "portable/plc/history.json")
                )
            }),
            ("public-blob", { root in
                let path = try XCTUnwrap(
                    regularFiles(under: root).first {
                        $0.hasPrefix("portable/blobs/public/")
                    }
                )
                try flipFirstByte(at: root.appending(path: path))
            }),
            ("space-car", { root in
                let path = try XCTUnwrap(
                    regularFiles(under: root).first {
                        $0.hasPrefix("portable/spaces/") && $0.hasSuffix(".car")
                    }
                )
                try flipFirstByte(at: root.appending(path: path))
            }),
            ("scalar-binding", { root in
                try rewriteEnvelope(in: root, key: fixture.backupKey) { plaintext in
                    var object = try XCTUnwrap(
                        JSONSerialization.jsonObject(with: plaintext)
                            as? [String: Any]
                    )
                    object["signingPrivateScalar"] =
                        Data(repeating: 0x6A, count: 32).base64URLEncoded
                    return try JSONSerialization.data(
                        withJSONObject: object,
                        options: [.sortedKeys, .withoutEscapingSlashes]
                    )
                }
            }),
            ("reference-binding", { root in
                try rewriteEnvelope(in: root, key: fixture.backupKey) { plaintext in
                    var object = try XCTUnwrap(
                        JSONSerialization.jsonObject(with: plaintext)
                            as? [String: Any]
                    )
                    var reference = try XCTUnwrap(
                        object["rotationKeyReference"] as? [String: Any]
                    )
                    reference["generation"] = 2
                    reference["reference"] = "account-rotation:2"
                    object["rotationKeyReference"] = reference
                    return try JSONSerialization.data(
                        withJSONObject: object,
                        options: [.sortedKeys, .withoutEscapingSlashes]
                    )
                }
            }),
        ]

        for (index, namedMutation) in mutations.enumerated() {
            let (name, mutate) = namedMutation
            let backup = try await fixture.completedBackup(
                named: "negative-\(index)-\(name)"
            )
            try mutate(backup)
            let sourceBefore = try treeSnapshot(backup)
            let target = fixture.root.appending(path: "negative-target-\(index)")
            await XCTAssertThrowsErrorAsync {
                _ = try await SwanOperatorAccountRestorer().restore(
                    backupAt: backup,
                    using: fixture.backupKey,
                    accountKEK: accountKEK,
                    to: target
                )
            }
            XCTAssertEqual(try treeSnapshot(backup), sourceBefore, name)
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.path), name)
            XCTAssertFalse(
                try FileManager.default.contentsOfDirectory(atPath: fixture.root.path)
                    .contains { $0.hasPrefix(".swan-account-restore-") },
                name
            )

            let valid = try await fixture.completedBackup(
                named: "negative-retry-\(index)"
            )
            _ = try await SwanOperatorAccountRestorer().restore(
                backupAt: valid,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: target
            )
            try FileManager.default.removeItem(at: target)
        }
    }

    func testDestinationLinkAndNestedWriteFailureLeaveNoTaskStateAndCanRetry()
        async throws
    {
        let fixture = try await OperatorBackupFixture()
        addTeardownBlock { try? await fixture.database.close(); fixture.remove() }
        let backup = try await fixture.completedBackup(named: "nested-failure-source")
        let accountKEK = try SwanOperatorAccountKEK(
            rawBytes: Data(repeating: 0xD4, count: 32)
        )
        let linkedTarget = fixture.root.appending(path: "linked-target")
        try FileManager.default.createSymbolicLink(
            at: linkedTarget,
            withDestinationURL: backup
        )
        await XCTAssertThrowsErrorAsync {
            _ = try await SwanOperatorAccountRestorer().restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: linkedTarget
            )
        }
        XCTAssertEqual(
            try FileManager.default.destinationOfSymbolicLink(
                atPath: linkedTarget.path
            ),
            backup.path
        )
        try FileManager.default.removeItem(at: linkedTarget)

        let target = fixture.root.appending(path: "nested-failure-target")
        let interrupted = SwanOperatorAccountRestorer(
            afterStagingBeforeInstall: {
                let stageName = try XCTUnwrap(
                    FileManager.default.contentsOfDirectory(atPath: fixture.root.path)
                        .first { $0.hasPrefix(".swan-account-restore-") }
                )
                try protectedWrite(
                    Data("blocks-key-directory".utf8),
                    to: fixture.root.appending(path: stageName).appending(path: "keys")
                )
            }
        )
        await XCTAssertThrowsErrorAsync {
            _ = try await interrupted.restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: target
            )
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
        XCTAssertFalse(
            try FileManager.default.contentsOfDirectory(atPath: fixture.root.path)
                .contains { $0.hasPrefix(".swan-account-restore-") }
        )
        await XCTAssertThrowsErrorAsync {
            _ = try await SwanOperatorAccountRestorer().restore(
                backupAt: backup,
                using: fixture.backupKey,
                accountKEK: accountKEK,
                to: target
            )
        }
    }
}

struct OperatorBackupFixture {
    let root: URL
    let database: SQLiteAccountDatabase
    let keyStore: FileAccountKeyStore
    let account: AccountControlAccount
    let credential: AccountControlCredential
    let backupKey: SwanOperatorBackupKey
    let accountKEK: Data
    let space: SpaceURI
    let initialRecordByteCount: Int
    let initialRecordValue: Data
    let password: String
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
        accountKEK = kek
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
        space = try SpaceURI(
            authority: did,
            spaceType: "app.example.room",
            skey: "restored"
        )
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
        let recordURI = try SpaceRecordURI(
            space: space,
            author: did,
            collection: "app.example.note",
            rkey: "one"
        )
        let recordValue = try DAGCBOR.encodeValue(
            OrderedCBORMap(entries: [(key: "text", value: "restore me")])
        )
        initialRecordByteCount = recordValue.count
        initialRecordValue = recordValue
        _ = try await database.apply(
            space: space,
            author: did,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try TID(tidString: "3jzfcijpj2z3a"),
            writes: [
                .create(
                    uri: recordURI,
                    value: recordValue,
                    cid: CID.fromDAGCBOR(recordValue).string
                ),
            ]
        )
        _ = try await database.putBlob(
            Data("operator-backup-space-blob".utf8),
            namespace: .space(space)
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
        password = "operator restore password"
        let passwordVerifier = try LibsodiumArgon2idHasher().hash(password)
        credential = try AccountControlCredential(
            did: did,
            verifier: passwordVerifier,
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let rawBackupKey = Data(repeating: 0xC3, count: 32)
        backupKey = try SwanOperatorBackupKey(rawBytes: rawBackupKey)
        secretSentinels = [
            kek,
            rawBackupKey,
            signingKey.rawRepresentation,
            rotationKey.rawRepresentation,
            Data(passwordVerifier.utf8),
        ]
    }

    func backup(to output: URL) async throws -> SwanOperatorAccountBackupResult {
        try await backup(
            to: output,
            continuityInventory:
                try PLCCredentialKeyContinuityInventory(checkpoints: [])
        )
    }

    func addSecondRepository() async throws -> Int {
        let secondSpace = try SpaceURI(
            authority: account.did,
            spaceType: "app.example.room",
            skey: "restored-second"
        )
        let value = try DAGCBOR.encodeValue(
            OrderedCBORMap(entries: [(key: "text", value: "restore me too")])
        )
        let uri = try SpaceRecordURI(
            space: secondSpace,
            author: account.did,
            collection: "app.example.note",
            rkey: "two"
        )
        _ = try await database.apply(
            space: secondSpace,
            author: account.did,
            expectedRevision: 0,
            requestID: UUID(),
            wireRevision: try TID(tidString: "3jzfcijpj2z3b"),
            writes: [
                .create(
                    uri: uri,
                    value: value,
                    cid: CID.fromDAGCBOR(value).string
                ),
            ]
        )
        return value.count
    }

    func backup(
        to output: URL,
        continuityInventory: PLCCredentialKeyContinuityInventory
    ) async throws -> SwanOperatorAccountBackupResult {
        try await SwanOperatorAccountBackupExporter(
            database: database,
            keyReader: keyStore,
            now: { Date(timeIntervalSince1970: 1_700_000_000) },
            continuityInventory: {
                continuityInventory
            }
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
        try? FileManager.default.removeItem(at: root)
    }
}

private final class UnsafeSendableBox<Value>: @unchecked Sendable {
    var value: Value

    init(_ value: Value) {
        self.value = value
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
    let profileID = try XCTUnwrap(object["profileID"] as? String)
    let envelopeURL = root.appending(path: "operator/secrets.aesgcm")
    let envelope = try Data(contentsOf: envelopeURL)
    let aad = Data(
        [
            "swan-operator-account-backup-v1",
            profileID,
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

private func decryptedEnvelope(
    in root: URL,
    key: SwanOperatorBackupKey
) throws -> Data {
    let manifestURL = root.appending(path: "manifest.json")
    let object = try XCTUnwrap(
        JSONSerialization.jsonObject(with: Data(contentsOf: manifestURL))
            as? [String: Any]
    )
    let portableDigest = try XCTUnwrap(
        object["portableManifestSHA256"] as? String
    )
    let profileID = try XCTUnwrap(object["profileID"] as? String)
    return try AES.GCM.open(
        AES.GCM.SealedBox(
            combined: Data(
                contentsOf: root.appending(path: "operator/secrets.aesgcm")
            )
        ),
        using: SymmetricKey(data: key.bytes),
        authenticating: Data(
            [
                "swan-operator-account-backup-v1",
                profileID,
                portableDigest,
            ].joined(separator: "\u{0}").utf8
        )
    )
}

private func flipFirstByte(at url: URL) throws {
    var bytes = try Data(contentsOf: url)
    bytes[bytes.startIndex] ^= 0x01
    try bytes.write(to: url)
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

private func replaceFirstOccurrenceInPlace(
    _ original: Data,
    with replacement: Data,
    in url: URL
) throws {
    precondition(original.count == replacement.count)
    let bytes = try Data(contentsOf: url)
    let range = try XCTUnwrap(bytes.range(of: original))
    XCTAssertNil(bytes[range.upperBound...].range(of: original))
    let handle = try FileHandle(forUpdating: url)
    defer { try? handle.close() }
    try handle.seek(toOffset: UInt64(range.lowerBound))
    try handle.write(contentsOf: replacement)
    try handle.synchronize()
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
