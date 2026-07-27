import Crypto
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import SwanAccounts
import SwanPublicRepository
@_spi(PortableRestore) import SwanSQLite
import SwanSpaces
import SwanStorage

/// The sole public restore failure. Archive, cryptographic, filesystem, and
/// persistence details are deliberately indistinguishable.
public enum SwanOperatorAccountRestoreError: Error, Sendable, Equatable {
    case failed
}

/// Opaque active KEK for newly written account-key envelopes. It is never
/// encoded, printed, persisted in SQLite, or accepted as a literal CLI value.
public struct SwanOperatorAccountKEK: Sendable {
    let bytes: Data

    init(rawBytes: Data) throws {
        guard rawBytes.count == 32 else {
            throw SwanOperatorAccountRestoreError.failed
        }
        bytes = rawBytes
    }

    public init(secretFile: URL) throws {
        do {
            let mounted = try SwanOperatorBackupKey(secretFile: secretFile)
            try self.init(rawBytes: mounted.bytes)
        } catch {
            throw SwanOperatorAccountRestoreError.failed
        }
    }
}

/// Metadata-only success response for one atomically published data root.
public struct SwanOperatorAccountRestoreResult: Codable, Sendable, Equatable {
    public let canonicalHandle: String
    public let did: String
    public let fileCount: Int
    public let publicGenesisCommitCID: String
    public let status: String
    public let targetDataDirectory: String
}

/// Restores exactly one verified V1 operator backup into an absent Swan data
/// root. Permissioned repository payloads are preserved but remain
/// HTTP-closed because V1 carries no authenticated authority policy.
public struct SwanOperatorAccountRestorer: Sendable {
    private let afterStagingBeforeInstall: (@Sendable (URL) throws -> Void)?
    private let afterStagingBeforeValidation: (@Sendable () throws -> Void)?
    private let afterRenameBeforeParentSync: (@Sendable () throws -> Void)?

    public init() {
        afterStagingBeforeInstall = nil
        afterStagingBeforeValidation = nil
        afterRenameBeforeParentSync = nil
    }

    init(
        afterStagingBeforeInstall: (@Sendable (URL) throws -> Void)? = nil,
        afterStagingBeforeValidation: (@Sendable () throws -> Void)? = nil,
        afterRenameBeforeParentSync: (@Sendable () throws -> Void)? = nil
    ) {
        self.afterStagingBeforeInstall = afterStagingBeforeInstall
        self.afterStagingBeforeValidation = afterStagingBeforeValidation
        self.afterRenameBeforeParentSync = afterRenameBeforeParentSync
    }

    public func restore(
        backupAt source: URL,
        using backupKey: SwanOperatorBackupKey,
        accountKEK: SwanOperatorAccountKEK,
        accountKEKID: String = "primary",
        to targetDataDirectory: URL
    ) async throws -> SwanOperatorAccountRestoreResult {
        do {
            return try await performRestore(
                backupAt: source,
                using: backupKey,
                accountKEK: accountKEK,
                accountKEKID: accountKEKID,
                to: targetDataDirectory
            )
        } catch {
            throw SwanOperatorAccountRestoreError.failed
        }
    }

    private func performRestore(
        backupAt source: URL,
        using backupKey: SwanOperatorBackupKey,
        accountKEK: SwanOperatorAccountKEK,
        accountKEKID: String,
        to targetDataDirectory: URL
    ) async throws -> SwanOperatorAccountRestoreResult {
        // Complete cryptographic/archive preflight while the destination path
        // remains entirely unprobed.
        let sourceRoot = try SwanPortableExportFilesystem.openArchiveRoot(source)
        defer { _ = close(sourceRoot) }
        let payload = try SwanOperatorAccountBackupVerifier.verifiedPayload(
            directoryDescriptor: sourceRoot,
            using: backupKey
        )
        guard payload.portable.manifest.includesPrivateKeys == false else {
            throw SwanOperatorAccountRestoreError.failed
        }
        let portableRoot = try SwanPortableExportFilesystem.openOwnerOnlyDirectory(
            parent: sourceRoot,
            name: "portable"
        )
        defer { _ = close(portableRoot) }
        let repeatedPortable = try SwanPortableExportVerifier.verifySelfContainedArchive(
            directoryDescriptor: portableRoot
        )
        guard repeatedPortable.manifestSHA256 == payload.portable.manifestSHA256,
              repeatedPortable.manifest == payload.portable.manifest,
              repeatedPortable.signingPublicKey.compressedRepresentation
                == payload.portable.signingPublicKey.compressedRepresentation else {
            throw SwanOperatorAccountRestoreError.failed
        }
        let artifacts = try readAndReverifyArtifacts(
            payload: payload,
            portableRoot: portableRoot
        )

        let configuration = try AccountKeyEncryptionConfiguration(
            activeKeyID: accountKEKID,
            activeKey: accountKEK.bytes
        )
        let destination = try SwanPortableExportDestination(targetDataDirectory)
        try SwanPortableExportFilesystem.requireNotWithin(
            directory: destination.parentDescriptor,
            ancestor: sourceRoot
        )
        let stagingName = ".swan-account-restore-\(UUID().uuidString.lowercased())"
        let stagingDescriptor = try SwanPortableExportFilesystem.createStagingDirectory(
            parent: destination.parentDescriptor,
            name: stagingName
        )
        do {
            try destination.requireCurrentParentAndAbsentTarget()
            guard try SwanPortableExportFilesystem.currentChildDirectoryMatches(
                parent: destination.parentDescriptor,
                name: stagingName,
                expectedDescriptor: stagingDescriptor
            ) else {
                throw SwanOperatorAccountRestoreError.failed
            }
            var stagingURL = try SwanPortableExportFilesystem.currentURL(
                for: stagingDescriptor
            )
            try afterStagingBeforeInstall?(stagingURL)
            stagingURL = try SwanPortableExportFilesystem.currentURL(
                for: stagingDescriptor
            )

            let signingPrivateKey = try P256.Signing.PrivateKey(
                rawRepresentation: payload.secrets.signingPrivateScalar
            )
            let rotationPrivateKey = try P256.Signing.PrivateKey(
                rawRepresentation: payload.secrets.rotationPrivateScalar
            )
            guard signingPrivateKey.publicKey.compressedRepresentation
                    == payload.portable.signingPublicKey.compressedRepresentation else {
                throw SwanOperatorAccountRestoreError.failed
            }

            try await installKeys(
                at: stagingURL.appending(path: "keys", directoryHint: .isDirectory),
                stagingRoot: stagingURL,
                expectedStagingDescriptor: stagingDescriptor,
                configuration: configuration,
                secrets: payload.secrets
            )
            try SwanPortableExportFilesystem.requireCurrentOwnerOnlyDirectory(
                stagingURL,
                matches: stagingDescriptor
            )

            stagingURL = try SwanPortableExportFilesystem.currentURL(
                for: stagingDescriptor
            )
            let database = try await SQLiteAccountDatabase(
                dataDirectory: stagingURL,
                did: payload.secrets.did
            )
            do {
                try SwanPortableExportFilesystem.requireCurrentOwnerOnlyDirectory(
                    stagingURL,
                    matches: stagingDescriptor
                )
                _ = try await database.installPublicRepositoryGenesis(
                    artifacts.publicGenesis,
                    signingPublicKey: signingPrivateKey.publicKey,
                    installedAt: artifacts.createdAt
                )
                try await database.restorePortableRepositories(artifacts.repositories)
                for blob in artifacts.blobs {
                    _ = try await database.restorePortableBlob(
                        blob.data,
                        expectedCID: blob.reference.cid,
                        namespace: blob.reference.namespace
                    )
                }
                try await database.validatePortableRestore(
                    repositories: artifacts.repositories
                )
                let inventory = try await database.portableExportInventory()
                guard inventory.repositories == artifacts.repositories.map({
                    .init(space: $0.space, author: $0.author)
                }),
                inventory.blobs == artifacts.blobs.map(\.reference) else {
                    throw SwanOperatorAccountRestoreError.failed
                }
                try await database.close()
                try SwanPortableExportFilesystem.requireCurrentOwnerOnlyDirectory(
                    stagingURL,
                    matches: stagingDescriptor
                )
            } catch {
                try? await database.close()
                throw error
            }

            stagingURL = try SwanPortableExportFilesystem.currentURL(
                for: stagingDescriptor
            )
            let control = try await SQLiteControlDatabase(dataDirectory: stagingURL)
            do {
                try SwanPortableExportFilesystem.requireCurrentOwnerOnlyDirectory(
                    stagingURL,
                    matches: stagingDescriptor
                )
                let account = try await control.createAccount(
                    AccountControlRegistration(
                        did: payload.secrets.did,
                        canonicalHandle: payload.secrets.canonicalHandle,
                        passwordVerifier: payload.secrets.passwordVerifier,
                        signingKey: payload.secrets.signingKeyReference,
                        rotationKey: payload.secrets.rotationKeyReference,
                        publicGenesisCommitCID:
                            payload.secrets.publicGenesisCommitCID,
                        createdAt: artifacts.createdAt
                    )
                )
                guard account.status == .active,
                      try await control.activeAccountDIDs() == [payload.secrets.did] else {
                    throw SwanOperatorAccountRestoreError.failed
                }
                try await control.validateOperatorRestoreOnlyAccount(
                    did: payload.secrets.did
                )
                try await control.close()
                try SwanPortableExportFilesystem.requireCurrentOwnerOnlyDirectory(
                    stagingURL,
                    matches: stagingDescriptor
                )
            } catch {
                try? await control.close()
                throw error
            }

            try afterStagingBeforeValidation?()
            try destination.requireCurrentParentAndAbsentTarget()
            guard try SwanPortableExportFilesystem.currentChildDirectoryMatches(
                parent: destination.parentDescriptor,
                name: stagingName,
                expectedDescriptor: stagingDescriptor
            ) else {
                throw SwanOperatorAccountRestoreError.failed
            }
            stagingURL = try SwanPortableExportFilesystem.currentURL(
                for: stagingDescriptor
            )
            try await validateReopenedStaging(
                at: stagingURL,
                payload: payload,
                artifacts: artifacts,
                configuration: configuration,
                expectedSigningPublicKey: signingPrivateKey.publicKey,
                expectedRotationPublicKey: rotationPrivateKey.publicKey
            )
            try SwanPortableExportFilesystem.requireCurrentOwnerOnlyDirectory(
                stagingURL,
                matches: stagingDescriptor
            )
            try SwanPortableExportFilesystem.synchronizeTree(root: stagingDescriptor)
            try destination.requireCurrentParentAndAbsentTarget()
            try SwanPortableExportFilesystem.renameExclusively(
                parent: destination.parentDescriptor,
                source: stagingName,
                destination: destination.outputName
            )
            try afterRenameBeforeParentSync?()
            try SwanPortableExportFilesystem.synchronizeParent(
                destination.parentDescriptor
            )
            try destination.requireCurrentParentAndInstalledTarget()
            guard try SwanPortableExportFilesystem.currentChildDirectoryMatches(
                parent: destination.parentDescriptor,
                name: destination.outputName,
                expectedDescriptor: stagingDescriptor
            ) else {
                throw SwanOperatorAccountRestoreError.failed
            }
            _ = close(stagingDescriptor)
            return SwanOperatorAccountRestoreResult(
                canonicalHandle: payload.verification.canonicalHandle,
                did: payload.verification.did,
                fileCount: payload.verification.fileCount,
                publicGenesisCommitCID:
                    payload.verification.publicGenesisCommitCID,
                status: "restored",
                targetDataDirectory: destination.url.path
            )
        } catch {
            do {
                try SwanPortableExportFilesystem.removeTree(
                    parent: destination.parentDescriptor,
                    matching: stagingDescriptor
                )
                try SwanPortableExportFilesystem.synchronizeParent(
                    destination.parentDescriptor
                )
            } catch {
                _ = close(stagingDescriptor)
                throw SwanOperatorAccountRestoreError.failed
            }
            _ = close(stagingDescriptor)
            throw SwanOperatorAccountRestoreError.failed
        }
    }

    private struct RestoredBlob: Sendable {
        let reference: BlobReference
        let data: Data
    }

    private struct Artifacts: Sendable {
        let publicGenesis: PublicRepositoryGenesis
        let repositories: [SQLitePortableRestoreRepository]
        let blobs: [RestoredBlob]
        let createdAt: Date
    }

    private func readAndReverifyArtifacts(
        payload: SwanOperatorVerifiedBackupPayload,
        portableRoot: Int32
    ) throws -> Artifacts {
        let manifest = payload.portable.manifest
        guard let publicEntry = manifest.files.first(where: {
            $0.type == .publicCAR && $0.path == "public/repository.car"
        }) else {
            throw SwanOperatorAccountRestoreError.failed
        }
        let publicCAR = try read(entry: publicEntry, root: portableRoot)
        let publicGenesis = try PublicRepositoryGenesisCodec.verify(
            car: publicCAR,
            publicKey: payload.portable.signingPublicKey
        )
        guard publicGenesis.did == manifest.did,
              publicGenesis.commitCID.string
                == payload.verification.publicGenesisCommitCID else {
            throw SwanOperatorAccountRestoreError.failed
        }

        var repositories: [SQLitePortableRestoreRepository] = []
        var blobs: [RestoredBlob] = []
        for entry in manifest.files {
            switch entry.type {
            case .spaceCAR:
                let components = entry.path.split(separator: "/").map(String.init)
                let space = try SpaceURI(
                    SwanPortableExportPath.decode(components[1])
                )
                let author = try SwanPortableExportPath.decode(
                    String(components[2].dropLast(4))
                )
                let recovery = try SpaceCARCodec.verifyRecovery(
                    read(entry: entry, root: portableRoot),
                    space: space,
                    author: author,
                    publicKey: payload.portable.signingPublicKey
                )
                repositories.append(
                    SQLitePortableRestoreRepository(
                        space: space,
                        author: author,
                        recovery: recovery
                    )
                )
            case .publicBlob:
                let components = entry.path.split(separator: "/").map(String.init)
                let cid = try SwanPortableExportPath.decode(components[2])
                blobs.append(
                    RestoredBlob(
                        reference: BlobReference(cid: cid, namespace: .public),
                        data: try read(entry: entry, root: portableRoot)
                    )
                )
            case .spaceBlob:
                let components = entry.path.split(separator: "/").map(String.init)
                let space = try SpaceURI(
                    SwanPortableExportPath.decode(components[2])
                )
                let cid = try SwanPortableExportPath.decode(components[3])
                blobs.append(
                    RestoredBlob(
                        reference: BlobReference(
                            cid: cid,
                            namespace: .space(space)
                        ),
                        data: try read(entry: entry, root: portableRoot)
                    )
                )
            case .publicCAR, .plcHistory:
                continue
            }
        }
        repositories.sort {
            ($0.space.rawValue, $0.author) < ($1.space.rawValue, $1.author)
        }
        blobs.sort {
            blobSortKey($0.reference) < blobSortKey($1.reference)
        }
        return Artifacts(
            publicGenesis: publicGenesis,
            repositories: repositories,
            blobs: blobs,
            createdAt: try canonicalDate(manifest.createdAt)
        )
    }

    private func read(
        entry: SwanPortableExportFile,
        root: Int32
    ) throws -> Data {
        let maximum = entry.type == .plcHistory
            ? 64 * 1_024
            : SwanPortableExportFilesystem.maximumArtifactBytes
        let data = try SwanPortableExportFilesystem.read(
            path: entry.path,
            root: root,
            maximumBytes: maximum
        )
        guard data.count == entry.byteCount,
              SwanPortableExportDigest.hex(data) == entry.sha256 else {
            throw SwanOperatorAccountRestoreError.failed
        }
        return data
    }

    private func installKeys(
        at root: URL,
        stagingRoot: URL,
        expectedStagingDescriptor: Int32,
        configuration: AccountKeyEncryptionConfiguration,
        secrets: SwanOperatorAccountSecrets
    ) async throws {
        let keyStore = try FileAccountKeyStore(
            root: root,
            configuration: configuration
        )
        try SwanPortableExportFilesystem.requireCurrentOwnerOnlyDirectory(
            stagingRoot,
            matches: expectedStagingDescriptor
        )
        try await keyStore.createBatch([
            AccountKeyMaterial(
                reference: try AccountKeyReference(
                    accountDID: secrets.did,
                    purpose: .signing,
                    generation: secrets.signingKeyReference.generation
                ),
                key: secrets.signingPrivateScalar
            ),
            AccountKeyMaterial(
                reference: try AccountKeyReference(
                    accountDID: secrets.did,
                    purpose: .rotation,
                    generation: secrets.rotationKeyReference.generation
                ),
                key: secrets.rotationPrivateScalar
            ),
        ])
        try SwanPortableExportFilesystem.requireCurrentOwnerOnlyDirectory(
            stagingRoot,
            matches: expectedStagingDescriptor
        )
    }

    private func validateReopenedStaging(
        at root: URL,
        payload: SwanOperatorVerifiedBackupPayload,
        artifacts: Artifacts,
        configuration: AccountKeyEncryptionConfiguration,
        expectedSigningPublicKey: P256.Signing.PublicKey,
        expectedRotationPublicKey: P256.Signing.PublicKey
    ) async throws {
        let control = try await SQLiteControlDatabase(
            dataDirectory: root,
            openMode: .existingPortableExportSource
        )
        do {
            let account = try await control.account(did: payload.secrets.did)
            let credential = try await control.credential(did: payload.secrets.did)
            guard account?.status == .active,
                  account?.canonicalHandle == payload.secrets.canonicalHandle,
                  account?.publicGenesisCommitCID
                    == payload.secrets.publicGenesisCommitCID,
                  account?.signingKey == payload.secrets.signingKeyReference,
                  account?.rotationKey == payload.secrets.rotationKeyReference,
                  credential?.verifier == payload.secrets.passwordVerifier,
                  try await control.activeAccountDIDs() == [payload.secrets.did]
            else {
                throw SwanOperatorAccountRestoreError.failed
            }
            try await control.validateOperatorRestoreOnlyAccount(
                did: payload.secrets.did
            )
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }

        let signingReference = try AccountKeyReference(
            accountDID: payload.secrets.did,
            purpose: .signing,
            generation: payload.secrets.signingKeyReference.generation
        )
        let rotationReference = try AccountKeyReference(
            accountDID: payload.secrets.did,
            purpose: .rotation,
            generation: payload.secrets.rotationKeyReference.generation
        )
        let keyReader = try ExistingFileAccountKeyReader(
            root: root.appending(path: "keys", directoryHint: .isDirectory),
            configuration: configuration
        )
        let signing = try P256.Signing.PrivateKey(
            rawRepresentation: await keyReader.key(for: signingReference)
        )
        let rotation = try P256.Signing.PrivateKey(
            rawRepresentation: await keyReader.key(for: rotationReference)
        )
        guard signing.publicKey.compressedRepresentation
                == expectedSigningPublicKey.compressedRepresentation,
              rotation.publicKey.compressedRepresentation
                == expectedRotationPublicKey.compressedRepresentation else {
            throw SwanOperatorAccountRestoreError.failed
        }

        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: payload.secrets.did,
            openMode: .existingPortableExportSource
        )
        do {
            let genesis = try await database.loadPublicRepositoryGenesis(
                did: payload.secrets.did,
                signingPublicKey: signing.publicKey
            )
            guard genesis?.genesis == artifacts.publicGenesis else {
                throw SwanOperatorAccountRestoreError.failed
            }
            try await database.validatePortableRestore(
                repositories: artifacts.repositories
            )
            let inventory = try await database.portableExportInventory()
            guard inventory.repositories == artifacts.repositories.map({
                .init(space: $0.space, author: $0.author)
            }),
            inventory.blobs == artifacts.blobs.map(\.reference) else {
                throw SwanOperatorAccountRestoreError.failed
            }
            for blob in artifacts.blobs {
                guard try await database.data(for: blob.reference) == blob.data else {
                    throw SwanOperatorAccountRestoreError.failed
                }
            }
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    private func canonicalDate(_ text: String) throws -> Date {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [
            .withInternetDateTime, .withFractionalSeconds,
            .withDashSeparatorInDate, .withColonSeparatorInTime,
        ]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        guard let date = formatter.date(from: text),
              formatter.string(from: date) == text else {
            throw SwanOperatorAccountRestoreError.failed
        }
        return date
    }

    private func blobSortKey(_ reference: BlobReference) -> String {
        switch reference.namespace {
        case .public:
            "public\u{0}\(reference.cid)"
        case let .space(space):
            "space\u{0}\(space.rawValue)\u{0}\(reference.cid)"
        }
    }
}
