import Crypto
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import PetrelCrypto
import PetrelPLC
@_spi(OperatorRestore) import SwanAccounts
import PetrelRepo
@_spi(PortableRestore) import SwanSQLite
import SwanSpaces
import SwanStorage

/// The sole public restore failure. Archive, cryptographic, filesystem, and
/// persistence details are deliberately indistinguishable.
public enum SwanOperatorAccountRestoreError: Error, Sendable, Equatable {
    case failed
    /// The backup authenticated, but its encrypted payload predates mandatory
    /// PLC credential-key continuity preservation.
    case unsupportedVersion
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
    /// Account content and keys are restored. Authority policies, members,
    /// writer inventory, registrations and outboxes require reconstruction.
    public let restoreScope: String = "account-content"
    public let permissionedAuthorityReady: Bool = false
}

/// Restores exactly one verified outer-V1/inner-V2-or-V3 operator backup into an
/// absent Swan data root. Permissioned repository payloads are preserved but
/// remain HTTP-closed because this format carries no authenticated authority
/// policy.
public struct SwanOperatorAccountRestorer: Sendable {
    private let afterStagingBeforeInstall: (@Sendable () throws -> Void)?
    private let afterStagingPathValidatedBeforeStorageOpen: (@Sendable () throws -> Void)?
    private let afterStagingBeforeValidation: (@Sendable () throws -> Void)?
    private let afterRenameBeforeParentSync: (@Sendable () throws -> Void)?
    private let afterCleanupEntryResolvedBeforeRemoval: (@Sendable (String) throws -> Void)?
    private let afterQuarantineMoveBeforeValidation: (@Sendable () throws -> Void)?
    private let maximumLogicalRestoredBytes: Int

    public init() {
        afterStagingBeforeInstall = nil
        afterStagingPathValidatedBeforeStorageOpen = nil
        afterStagingBeforeValidation = nil
        afterRenameBeforeParentSync = nil
        afterCleanupEntryResolvedBeforeRemoval = nil
        afterQuarantineMoveBeforeValidation = nil
        maximumLogicalRestoredBytes =
            SwanPortableExportFilesystem.maximumArchiveBytes
    }

    init(
        afterStagingBeforeInstall: (@Sendable () throws -> Void)? = nil,
        afterStagingPathValidatedBeforeStorageOpen: (@Sendable () throws -> Void)? = nil,
        afterStagingBeforeValidation: (@Sendable () throws -> Void)? = nil,
        afterRenameBeforeParentSync: (@Sendable () throws -> Void)? = nil,
        afterCleanupEntryResolvedBeforeRemoval: (@Sendable (String) throws -> Void)? = nil,
        afterQuarantineMoveBeforeValidation: (@Sendable () throws -> Void)? = nil,
        maximumLogicalRestoredBytes: Int =
            SwanPortableExportFilesystem.maximumArchiveBytes
    ) {
        precondition(maximumLogicalRestoredBytes > 0)
        self.afterStagingBeforeInstall = afterStagingBeforeInstall
        self.afterStagingPathValidatedBeforeStorageOpen =
            afterStagingPathValidatedBeforeStorageOpen
        self.afterStagingBeforeValidation = afterStagingBeforeValidation
        self.afterRenameBeforeParentSync = afterRenameBeforeParentSync
        self.afterCleanupEntryResolvedBeforeRemoval =
            afterCleanupEntryResolvedBeforeRemoval
        self.afterQuarantineMoveBeforeValidation =
            afterQuarantineMoveBeforeValidation
        self.maximumLogicalRestoredBytes = maximumLogicalRestoredBytes
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
        } catch is SwanOperatorAccountBackupCompatibilityError {
            throw SwanOperatorAccountRestoreError.unsupportedVersion
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
        let payload = try await SwanOperatorAccountBackupVerifier
            .verifiedPayloadStreaming(
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
        let repeatedPortable = try await SwanPortableExportVerifier
            .verifySelfContainedArchiveStreaming(
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
            try afterStagingBeforeInstall?()
            try afterStagingPathValidatedBeforeStorageOpen?()

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

            let keysDirectory = try SwanPortableExportFilesystem
                .openOrCreateOwnerOnlyDirectory(
                    parent: stagingDescriptor,
                    name: "keys"
                ).descriptor
            defer { _ = close(keysDirectory) }
            try await installKeys(
                directoryDescriptor: keysDirectory,
                configuration: configuration,
                secrets: payload.secrets
            )

            let database = try await SQLiteAccountDatabase(
                dataDirectory: destination.url,
                did: payload.secrets.did,
                openMode: .descriptorBackedOperatorRestore(
                    rootDescriptor: stagingDescriptor
                )
            )
            var installedRepositories: [SQLitePortableRestoreRepositoryMetadata] = []
            var installedLogicalRestoredBytes = 0
            do {
                _ = try await database.installPublicRepositoryGenesis(
                    artifacts.publicGenesis,
                    signingPublicKey: signingPrivateKey.publicKey,
                    installedAt: artifacts.createdAt
                )
                let initialJournal = try PLCAccountPreparationJournal(
                    requestID: artifacts.preparationJournal.requestID,
                    canonicalHandle: artifacts.preparationJournal.canonicalHandle,
                    pdsOrigin: artifacts.preparationJournal.pdsOrigin,
                    repositoryRevision: artifacts.preparationJournal.repositoryRevision,
                    operation: artifacts.preparationJournal.operation,
                    signingKey: artifacts.preparationJournal.signingKey,
                    rotationKey: artifacts.preparationJournal.rotationKey,
                    publicGenesisCommitCID: nil,
                    stage: .keysStored
                )
                _ = try await database.installPLCAccountPreparationJournal(
                    initialJournal
                )
                _ = try await database.advancePLCAccountPreparationJournal(
                    requestID: initialJournal.requestID,
                    expectedStage: .keysStored,
                    to: .repositoryInstalled,
                    publicGenesisCommitCID: artifacts.publicGenesis.commitCID.string
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
                for entry in artifacts.plcHistoryEntries {
                    _ = try await database.installPublicPLCOperation(entry)
                }
                for repository in artifacts.repositories {
                    try Task.checkCancellation()
                    let metadata = try await installRepository(
                        repository,
                        portableRoot: portableRoot,
                        signingPublicKey: payload.portable.signingPublicKey,
                        database: database,
                        maximumLogicalRestoredBytes:
                            maximumLogicalRestoredBytes
                                - installedLogicalRestoredBytes
                    )
                    let (nextLogicalRestoredBytes, overflow) =
                        installedLogicalRestoredBytes.addingReportingOverflow(
                            metadata.logicalRestoredByteCount
                        )
                    guard !overflow,
                          nextLogicalRestoredBytes
                            <= maximumLogicalRestoredBytes else {
                        throw SwanOperatorAccountRestoreError.failed
                    }
                    installedLogicalRestoredBytes = nextLogicalRestoredBytes
                    installedRepositories.append(metadata)
                }
                for blob in artifacts.blobs {
                    try Task.checkCancellation()
                    try await installBlob(
                        blob,
                        portableRoot: portableRoot,
                        database: database
                    )
                }
                try await database.validatePortableRestoreStreaming(
                    repositories: installedRepositories
                )
                let inventory = try await database.portableExportInventory()
                guard inventory.repositories == installedRepositories.map({
                    .init(space: $0.space, author: $0.author)
                }),
                inventory.blobs == artifacts.blobs.map(\.reference) else {
                    throw SwanOperatorAccountRestoreError.failed
                }
                try await database.close()
            } catch {
                try? await database.close()
                throw error
            }

            let control = try await SQLiteControlDatabase(
                dataDirectory: destination.url,
                openMode: .descriptorBackedOperatorRestore(
                    rootDescriptor: stagingDescriptor
                )
            )
            do {
                let account =
                    try await control
                        .restoreOperatorAccountAndPLCCredentialKeyContinuity(
                            AccountControlRegistration(
                                did: payload.secrets.did,
                                canonicalHandle:
                                    payload.secrets.canonicalHandle,
                                passwordVerifier:
                                    payload.secrets.passwordVerifier,
                                signingKey:
                                    payload.secrets.signingKeyReference,
                                rotationKey:
                                    payload.secrets.rotationKeyReference,
                                publicGenesisCommitCID:
                                    payload.secrets.publicGenesisCommitCID,
                                createdAt: artifacts.createdAt
                            ),
                            checkpoints:
                                payload.secrets.plcCredentialKeyContinuity
                                    .checkpoints,
                            plcAccountPreparationIntent:
                                artifacts.preparationIntent
                        )
                guard account.status == .active,
                      try await control.activeAccountDIDs() == [payload.secrets.did] else {
                    throw SwanOperatorAccountRestoreError.failed
                }
                try await control.validateOperatorRestoreOnlyAccount(
                    did: payload.secrets.did,
                    plcCredentialKeyContinuity:
                        payload.secrets.plcCredentialKeyContinuity.checkpoints,
                    plcAccountPreparationIntent:
                        artifacts.preparationIntent
                )
                try await control.close()
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
            try await validateReopenedStaging(
                rootDescriptor: stagingDescriptor,
                keyDirectoryDescriptor: keysDirectory,
                displayURL: destination.url,
                payload: payload,
                artifacts: artifacts,
                installedRepositories: installedRepositories,
                configuration: configuration,
                expectedSigningPublicKey: signingPrivateKey.publicKey,
                expectedRotationPublicKey: rotationPrivateKey.publicKey
            )
            try SwanPortableExportFilesystem.synchronizeTree(root: stagingDescriptor)
            try destination.requireCurrentParentAndAbsentTarget()
            try Task.checkCancellation()
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
            try await validateReopenedStaging(
                rootDescriptor: stagingDescriptor,
                keyDirectoryDescriptor: keysDirectory,
                displayURL: destination.url,
                payload: payload,
                artifacts: artifacts,
                installedRepositories: installedRepositories,
                configuration: configuration,
                expectedSigningPublicKey: signingPrivateKey.publicKey,
                expectedRotationPublicKey: rotationPrivateKey.publicKey
            )
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
                    matching: stagingDescriptor,
                    afterEntryResolvedBeforeRemoval:
                        afterCleanupEntryResolvedBeforeRemoval,
                    afterQuarantineMoveBeforeValidation:
                        afterQuarantineMoveBeforeValidation
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
        let entry: SwanPortableExportFile
        let reference: BlobReference
    }

    private struct RestoredRepository: Sendable {
        let entry: SwanPortableExportFile
        let space: SpaceURI
        let author: String
    }

    private struct Artifacts: Sendable {
        let publicGenesis: PublicRepositoryGenesis
        let repositories: [RestoredRepository]
        let blobs: [RestoredBlob]
        let createdAt: Date
        let preparationJournal: PLCAccountPreparationJournal
        let preparationIntent: PLCAccountPreparationIntent
        let plcHistoryEntries: [PublicPLCOperationHistoryEntry]
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
        guard let historyEntry = manifest.files.first(where: {
            $0.type == .plcHistory && $0.path == "plc/history.json"
        }) else {
            throw SwanOperatorAccountRestoreError.failed
        }
        let plcHistory = try read(entry: historyEntry, root: portableRoot)
        let identity = try readPLCIdentity(
            plcHistory,
            expectedDID: manifest.did,
            expectedHandle: manifest.canonicalHandle,
            expectedRepositoryRevision: publicGenesis.revision,
            expectedPublicGenesisCID: publicGenesis.commitCID.string,
            signingPublicKey: payload.portable.signingPublicKey,
            rotationPublicKey: try P256.Signing.PrivateKey(
                rawRepresentation: payload.secrets.rotationPrivateScalar
            ).publicKey
        )
        let requestID = "operator-restore-" + identity.operationCID
        let preparationIntent: PLCAccountPreparationIntent
        do {
            preparationIntent = try PLCAccountPreparationIntent(
                requestID: requestID,
                did: manifest.did,
                canonicalHandle: manifest.canonicalHandle,
                pdsOrigin: identity.pdsOrigin,
                repositoryRevision: publicGenesis.revision,
                operationCID: identity.operationCID,
                stage: .submitted
            )
        } catch {
            throw error
        }
        let preparationJournal: PLCAccountPreparationJournal
        do {
            preparationJournal = try PLCAccountPreparationJournal(
                requestID: requestID,
                canonicalHandle: manifest.canonicalHandle,
                pdsOrigin: identity.pdsOrigin,
                repositoryRevision: publicGenesis.revision,
                operation: identity.operationFacts,
                signingKey: payload.secrets.signingKeyReference,
                rotationKey: payload.secrets.rotationKeyReference,
                publicGenesisCommitCID: publicGenesis.commitCID.string,
                stage: .submitted
            )
        } catch {
            throw error
        }

        var repositories: [RestoredRepository] = []
        var blobs: [RestoredBlob] = []
        for entry in manifest.files {
            try Task.checkCancellation()
            switch entry.type {
            case .spaceCAR:
                let components = entry.path.split(separator: "/").map(String.init)
                let space = try SpaceURI(
                    SwanPortableExportPath.decode(components[1])
                )
                let author = try SwanPortableExportPath.decode(
                    String(components[2].dropLast(4))
                )
                repositories.append(
                    RestoredRepository(
                        entry: entry,
                        space: space,
                        author: author
                    )
                )
            case .publicBlob:
                let components = entry.path.split(separator: "/").map(String.init)
                let cid = try SwanPortableExportPath.decode(components[2])
                blobs.append(
                    RestoredBlob(
                        entry: entry,
                        reference: BlobReference(cid: cid, namespace: .public)
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
                        entry: entry,
                        reference: BlobReference(
                            cid: cid,
                            namespace: .space(space)
                        )
                    )
                )
            case .publicCAR, .plcHistory, .identitySnapshot:
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
            createdAt: try canonicalDate(manifest.createdAt),
            preparationJournal: preparationJournal,
            preparationIntent: preparationIntent,
            plcHistoryEntries: payload.secrets.plcIdentityHistory.isEmpty ? [identity.historyEntry] : payload.secrets.plcIdentityHistory
        )
    }

    private func installRepository(
        _ repository: RestoredRepository,
        portableRoot: Int32,
        signingPublicKey: P256.Signing.PublicKey,
        database: SQLiteAccountDatabase,
        maximumLogicalRestoredBytes: Int
    ) async throws -> SQLitePortableRestoreRepositoryMetadata {
        let source = try SwanPortableExportFileByteSource(
            path: repository.entry.path,
            root: portableRoot
        )
        let staging: SQLiteSpaceCARRecoveryIndex
        do {
            staging = try await SQLiteSpaceCARRecoveryIndex.create()
        } catch {
            await source.close()
            throw error
        }
        do {
            let verified = try await SpaceCARCodec.verifyStreamingRecovery(
                from: source,
                space: repository.space,
                author: repository.author,
                contextSignatureVerifier: { envelope in
                    try SpaceCommitCodec.verifyContextSignature(
                        envelope,
                        publicKey: signingPublicKey
                    )
                },
                index: staging,
                recordSink: staging
            )
            let digest = try await source.finish()
            guard digest.byteCount == repository.entry.byteCount,
                  digest.sha256 == repository.entry.sha256 else {
                throw SwanOperatorAccountRestoreError.failed
            }
            let metadata = SQLitePortableRestoreRepositoryMetadata(
                space: repository.space,
                author: repository.author,
                verification: verified
            )
            guard metadata.logicalRestoredByteCount
                    <= maximumLogicalRestoredBytes else {
                throw SwanOperatorAccountRestoreError.failed
            }
            try await database.restorePortableRepositoryStreaming(
                metadata,
                staging: staging
            )
            try Task.checkCancellation()
            await staging.cleanup()
            return metadata
        } catch {
            await source.close()
            await staging.cleanup()
            throw error
        }
    }

    private func installBlob(
        _ blob: RestoredBlob,
        portableRoot: Int32,
        database: SQLiteAccountDatabase
    ) async throws {
        let source = try SwanPortableExportFileByteSource(
            path: blob.entry.path,
            root: portableRoot
        )
        do {
            _ = try await database.restorePortableBlobStreaming(
                expectedCID: blob.reference.cid,
                expectedByteCount: blob.entry.byteCount,
                namespace: blob.reference.namespace
            ) { consume in
                while let chunk = try await source.read(
                    maximumBytes: SpaceCARRecoveryLimits.maximumChunkBytes
                ) {
                    try Task.checkCancellation()
                    try await consume(chunk)
                }
                let digest = try await source.finish()
                guard digest.byteCount == blob.entry.byteCount,
                      digest.sha256 == blob.entry.sha256 else {
                    throw SwanOperatorAccountRestoreError.failed
                }
            }
        } catch {
            await source.close()
            throw error
        }
    }

    private struct PLCIdentity: Sendable {
        let operationCID: String
        let pdsOrigin: String
        let operationFacts: PLCAccountPreparationOperationFacts
        let historyEntry: PublicPLCOperationHistoryEntry
    }

    private func readPLCIdentity(
        _ data: Data,
        expectedDID: String,
        expectedHandle: String,
        expectedRepositoryRevision: String,
        expectedPublicGenesisCID: String,
        signingPublicKey: P256.Signing.PublicKey,
        rotationPublicKey: P256.Signing.PublicKey
    ) throws -> PLCIdentity {
        let keys = Set([
            "format", "scope", "did", "operationCID", "operation",
            "canonicalHandle", "pdsOrigin", "repositoryRevision",
            "publicGenesisCommitCID", "signingKeyBinding",
        ])
        guard let object = try JSONSerialization.jsonObject(with: data)
                as? [String: Any],
              Set(object.keys) == keys,
              object["format"] as? String == "swan-plc-history-v1",
              object["scope"] as? String
                == SwanPortableExportManifest.plcHistoryScopeValue,
              object["signingKeyBinding"] as? String == "plc-atproto-current-v1",
              object["did"] as? String == expectedDID,
              object["canonicalHandle"] as? String == expectedHandle,
              object["repositoryRevision"] as? String == expectedRepositoryRevision,
              object["publicGenesisCommitCID"] as? String == expectedPublicGenesisCID,
              let operationCID = object["operationCID"] as? String,
              let pdsOrigin = object["pdsOrigin"] as? String,
              let operationObject = object["operation"] else {
            throw SwanOperatorAccountRestoreError.failed
        }
        let operationData = try JSONSerialization.data(
            withJSONObject: operationObject,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let operation = try PLCOperationCodec.decodeSignedJSON(operationData)
        try PLCOperationCodec.verifyGenesis(operation, expectedDID: expectedDID)
        guard let regular = operation.regular,
              try operation.cid.string == operationCID,
              regular.verificationMethods["atproto"]
                == P256DIDKey(publicKey: signingPublicKey).value,
              regular.rotationKeys == [
                  P256DIDKey(publicKey: rotationPublicKey).value
              ],
              regular.alsoKnownAs == ["at://\(expectedHandle)"],
              regular.services["atproto_pds"]?.endpoint == pdsOrigin,
              let signingDIDKey = regular.verificationMethods["atproto"],
              let rotationDIDKey = regular.rotationKeys.first else {
            throw SwanOperatorAccountRestoreError.failed
        }
        let facts = try PLCAccountPreparationOperationFacts(
            signingDIDKey: signingDIDKey,
            rotationDIDKey: rotationDIDKey,
            signature: regular.signature,
            kemDIDKey: regular.verificationMethods["atproto_kem"]
        )
        let historyEntry = try PublicPLCOperationHistoryEntry(
            cid: operationCID,
            previousCID: nil,
            canonicalJSON: operation.canonicalJSON,
            createdAt: Date(timeIntervalSince1970: 0),
            signingKeyGeneration: 1,
            rotationKeyGeneration: 1
        )
        return PLCIdentity(
            operationCID: operationCID,
            pdsOrigin: pdsOrigin,
            operationFacts: facts,
            historyEntry: historyEntry
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
        directoryDescriptor: Int32,
        configuration: AccountKeyEncryptionConfiguration,
        secrets: SwanOperatorAccountSecrets
    ) async throws {
        let keyStore = try FileAccountKeyStore(
            operatorRestoreDirectoryDescriptor: directoryDescriptor,
            configuration: configuration
        )
        var materials = try [
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
        ]
        if let kem = secrets.kemPrivateScalar {
            materials.append(try AccountKeyMaterial(reference: AccountKEMKeyProvider.reference(accountDID: secrets.did), key: kem))
        }
        try await keyStore.createBatch(materials)
    }

    private func validateReopenedStaging(
        rootDescriptor: Int32,
        keyDirectoryDescriptor: Int32,
        displayURL: URL,
        payload: SwanOperatorVerifiedBackupPayload,
        artifacts: Artifacts,
        installedRepositories: [SQLitePortableRestoreRepositoryMetadata],
        configuration: AccountKeyEncryptionConfiguration,
        expectedSigningPublicKey: P256.Signing.PublicKey,
        expectedRotationPublicKey: P256.Signing.PublicKey
    ) async throws {
        let control = try await SQLiteControlDatabase(
            dataDirectory: displayURL,
            openMode: .descriptorBackedOperatorRestoreSource(
                rootDescriptor: rootDescriptor
            )
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
                did: payload.secrets.did,
                plcCredentialKeyContinuity:
                    payload.secrets.plcCredentialKeyContinuity.checkpoints,
                plcAccountPreparationIntent: artifacts.preparationIntent
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
            operatorRestoreDirectoryDescriptor: keyDirectoryDescriptor,
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

        if let expectedKEM = payload.secrets.kemPrivateScalar {
            guard try await keyReader.key(for: AccountKEMKeyProvider.reference(accountDID: payload.secrets.did)) == expectedKEM else {
                throw SwanOperatorAccountRestoreError.failed
            }
        }

        let database = try await SQLiteAccountDatabase(
            dataDirectory: displayURL,
            did: payload.secrets.did,
            openMode: .descriptorBackedOperatorRestoreSource(
                rootDescriptor: rootDescriptor
            )
        )
        do {
            let genesis = try await database.loadPublicRepositoryGenesis(
                did: payload.secrets.did,
                signingPublicKey: signing.publicKey
            )
            guard genesis?.genesis == artifacts.publicGenesis else {
                throw SwanOperatorAccountRestoreError.failed
            }
            guard try await database.plcAccountPreparationJournal()
                    == artifacts.preparationJournal,
                  try await database.publicPLCOperationHistory()
                    == artifacts.plcHistoryEntries else {
                throw SwanOperatorAccountRestoreError.failed
            }
            try await database.validatePortableRestoreStreaming(
                repositories: installedRepositories
            )
            let inventory = try await database.portableExportInventory()
            guard inventory.repositories == installedRepositories.map({
                .init(space: $0.space, author: $0.author)
            }),
            inventory.blobs == artifacts.blobs.map(\.reference) else {
                throw SwanOperatorAccountRestoreError.failed
            }
            for blob in artifacts.blobs {
                try await database.validatePortableBlob(
                    blob.reference,
                    expectedByteCount: blob.entry.byteCount
                )
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
        case .staged:
            // An export inventory never contains a staged upload edge; keep
            // the ordering total rather than trapping on a value the caller
            // cannot produce.
            "staged\u{0}\(reference.cid)"
        }
    }
}
