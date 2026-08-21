import Crypto
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import SwanCore

public enum SwanPortableRestoreStatus: String, Codable, Sendable {
    case staged
    case alreadyStaged = "already-staged"
}

public struct SwanPortableRestoreResult: Codable, Sendable, Equatable {
    public let canonicalHandle: String
    public let did: String
    public let fileCount: Int
    public let includesPrivateKeys: Bool
    public let manifestSHA256: String
    public let profileID: String
    public let stagingDirectory: String
    public let status: SwanPortableRestoreStatus
}

public struct SwanPortableAccountRestoreStager: Sendable {
    private let afterRenameBeforeParentSync: (@Sendable () throws -> Void)?
    private let beforeSuccessIdentityValidation: (@Sendable () throws -> Void)?
    private let synchronizeCreatedDirectoryParent:
        @Sendable (Int32) throws -> Void
    private let beforeCleanupAttempt: (@Sendable (Int) throws -> Void)?
    private let identitySnapshotInstaller: (@Sendable (SwanIdentitySnapshot) async throws -> Void)?

    public init() {
        afterRenameBeforeParentSync = nil
        beforeSuccessIdentityValidation = nil
        synchronizeCreatedDirectoryParent = {
            try SwanPortableExportFilesystem.synchronizeParent($0)
        }
        beforeCleanupAttempt = nil
        identitySnapshotInstaller = nil
    }

    init(
        afterRenameBeforeParentSync: (@Sendable () throws -> Void)? = nil,
        beforeSuccessIdentityValidation: (@Sendable () throws -> Void)? = nil,
        synchronizeCreatedDirectoryParent:
            @escaping @Sendable (Int32) throws -> Void = {
                try SwanPortableExportFilesystem.synchronizeParent($0)
            },
        beforeCleanupAttempt: (@Sendable (Int) throws -> Void)? = nil,
        identitySnapshotInstaller: (@Sendable (SwanIdentitySnapshot) async throws -> Void)? = nil
    ) {
        self.afterRenameBeforeParentSync = afterRenameBeforeParentSync
        self.beforeSuccessIdentityValidation = beforeSuccessIdentityValidation
        self.synchronizeCreatedDirectoryParent = synchronizeCreatedDirectoryParent
        self.beforeCleanupAttempt = beforeCleanupAttempt
        self.identitySnapshotInstaller = identitySnapshotInstaller
    }

    public func stage(
        archiveAt inputDirectory: URL,
        dataDirectory: URL
    ) async throws -> SwanPortableRestoreResult {
        let sourceDescriptor = try SwanPortableExportFilesystem.openArchiveRoot(
            inputDirectory
        )
        defer { _ = close(sourceDescriptor) }

        // The archive is fully authenticated before the Swan data directory is
        // opened, inspected, or changed.
        let preflight = try await SwanPortableExportVerifier
            .verifySelfContainedArchiveStreaming(
            directoryDescriptor: sourceDescriptor
        )
        guard preflight.manifest.includesPrivateKeys == false,
              preflight.manifestSHA256.hasPrefix("sha256:") else {
            throw SwanPortableExportError.invalidArchive
        }
        let manifestHash = String(preflight.manifestSHA256.dropFirst("sha256:".count))
        guard SwanPortableExportDigest.isCanonicalHex(manifestHash) else {
            throw SwanPortableExportError.invalidArchive
        }

        let canonicalDataDirectory = dataDirectory.standardizedFileURL
        let dataDescriptor = try SwanPortableExportFilesystem.openExistingOwnerOnlyDirectory(
            canonicalDataDirectory
        )
        defer { _ = close(dataDescriptor) }

        let restoreParent = try SwanPortableExportFilesystem.openOrCreateOwnerOnlyDirectory(
            parent: dataDescriptor,
            name: "restore-staging"
        )
        defer { _ = close(restoreParent.descriptor) }

        do {
            if try SwanPortableExportFilesystem.entryExists(
                parent: restoreParent.descriptor,
                name: manifestHash
            ) {
                let existingDescriptor = try SwanPortableExportFilesystem.openOwnerOnlyDirectory(
                    parent: restoreParent.descriptor,
                    name: manifestHash
                )
                defer { _ = close(existingDescriptor) }
                let existing = try await SwanPortableExportVerifier
                    .verifySelfContainedArchiveStreaming(
                    directoryDescriptor: existingDescriptor
                )
                try requireSameIdentity(existing, preflight)
                if restoreParent.created {
                    try SwanPortableExportFilesystem.synchronizeParent(dataDescriptor)
                }
                try requireCurrentPublication(
                    dataDirectory: canonicalDataDirectory,
                    dataDescriptor: dataDescriptor,
                    restoreParentDescriptor: restoreParent.descriptor,
                    archiveDescriptor: existingDescriptor,
                    manifestHash: manifestHash
                )
                try await installIdentitySnapshotIfPresent(existing, archiveDescriptor: existingDescriptor)
                return result(
                    verification: existing,
                    dataDirectory: canonicalDataDirectory,
                    manifestHash: manifestHash,
                    status: .alreadyStaged
                )
            }

            let temporaryName = ".swan-restore-\(UUID().uuidString.lowercased())"
            let stagingDescriptor = try SwanPortableExportFilesystem.createStagingDirectory(
                parent: restoreParent.descriptor,
                name: temporaryName
            )
            do {
                try copyArchive(
                    preflight.manifest,
                    source: sourceDescriptor,
                    destination: stagingDescriptor
                )
                guard fsync(stagingDescriptor) == 0 else {
                    throw SwanPortableExportError.publicationFailed
                }
                let staged = try await SwanPortableExportVerifier
                    .verifySelfContainedArchiveStreaming(
                    directoryDescriptor: stagingDescriptor
                )
                try requireSameIdentity(staged, preflight)
                try Task.checkCancellation()
                try SwanPortableExportFilesystem.renameExclusively(
                    parent: restoreParent.descriptor,
                    source: temporaryName,
                    destination: manifestHash
                )
                try afterRenameBeforeParentSync?()
                try SwanPortableExportFilesystem.synchronizeParent(
                    restoreParent.descriptor
                )
                if restoreParent.created {
                    try SwanPortableExportFilesystem.synchronizeParent(dataDescriptor)
                }
                let installed = try await SwanPortableExportVerifier
                    .verifySelfContainedArchiveStreaming(
                        directoryDescriptor: stagingDescriptor
                    )
                try requireSameIdentity(installed, staged)
                try requireCurrentPublication(
                    dataDirectory: canonicalDataDirectory,
                    dataDescriptor: dataDescriptor,
                    restoreParentDescriptor: restoreParent.descriptor,
                    archiveDescriptor: stagingDescriptor,
                    manifestHash: manifestHash
                )
                try await installIdentitySnapshotIfPresent(installed, archiveDescriptor: stagingDescriptor)
                _ = close(stagingDescriptor)
                return result(
                    verification: installed,
                    dataDirectory: canonicalDataDirectory,
                    manifestHash: manifestHash,
                    status: .staged
                )
            } catch {
                do {
                    try removeTreeWithRetry(
                        parent: restoreParent.descriptor,
                        matching: stagingDescriptor
                    )
                } catch {
                    _ = close(stagingDescriptor)
                    throw SwanPortableExportError.publicationFailed
                }
                _ = close(stagingDescriptor)
                throw error
            }
        } catch {
            // Portable online cleanup never removes by pathname. The owner-only
            // parent is retained for retry or quiesced operator recovery.
            throw error
        }
    }

    private func copyArchive(
        _ manifest: SwanPortableExportManifest,
        source: Int32,
        destination: Int32
    ) throws {
        try SwanPortableExportFilesystem.copyStreaming(
            path: "manifest.json",
            sourceRoot: source,
            destinationRoot: destination,
            expectedByteCount: try SwanPortableExportFilesystem.fileByteCount(
                path: "manifest.json",
                root: source,
                maximumBytes: 4 * 1_024 * 1_024
            ),
            maximumBytes: 4 * 1_024 * 1_024,
            synchronizeCreatedDirectoryParent:
                synchronizeCreatedDirectoryParent
        )
        for entry in manifest.files {
            try Task.checkCancellation()
            let maximumBytes = switch entry.type {
            case .plcHistory: 64 * 1_024
            case .identitySnapshot: 64 * 1_024
            default: SwanPortableExportFilesystem.maximumArtifactBytes
            }
            try SwanPortableExportFilesystem.copyStreaming(
                path: entry.path,
                sourceRoot: source,
                destinationRoot: destination,
                expectedByteCount: entry.byteCount,
                maximumBytes: maximumBytes,
                synchronizeCreatedDirectoryParent:
                    synchronizeCreatedDirectoryParent
            )
        }
    }

    private func requireCurrentPublication(
        dataDirectory: URL,
        dataDescriptor: Int32,
        restoreParentDescriptor: Int32,
        archiveDescriptor: Int32,
        manifestHash: String
    ) throws {
        try beforeSuccessIdentityValidation?()
        try SwanPortableExportFilesystem.requireCurrentOwnerOnlyDirectory(
            dataDirectory,
            matches: dataDescriptor
        )
        try SwanPortableExportFilesystem.requireCurrentChildDirectory(
            parent: dataDescriptor,
            name: "restore-staging",
            matches: restoreParentDescriptor
        )
        try SwanPortableExportFilesystem.requireCurrentChildDirectory(
            parent: restoreParentDescriptor,
            name: manifestHash,
            matches: archiveDescriptor
        )
    }

    private func removeTreeWithRetry(
        parent: Int32,
        matching descriptor: Int32
    ) throws {
        for attempt in 1 ... 2 {
            do {
                try beforeCleanupAttempt?(attempt)
                try SwanPortableExportFilesystem.removeTree(
                    parent: parent,
                    matching: descriptor
                )
                return
            } catch {
                if attempt == 2 {
                    throw SwanPortableExportError.publicationFailed
                }
            }
        }
    }

    private func requireSameIdentity(
        _ candidate: SwanPortableArchiveVerification,
        _ expected: SwanPortableArchiveVerification
    ) throws {
        guard candidate.manifestSHA256 == expected.manifestSHA256,
              candidate.manifest.did == expected.manifest.did,
              candidate.manifest.canonicalHandle == expected.manifest.canonicalHandle,
              candidate.manifest.profileID == expected.manifest.profileID,
              candidate.manifest.includesPrivateKeys == false,
              candidate.signingPublicKey.compressedRepresentation
                == expected.signingPublicKey.compressedRepresentation else {
            throw SwanPortableExportError.invalidArchive
        }
    }

    private func result(
        verification: SwanPortableArchiveVerification,
        dataDirectory: URL,
        manifestHash: String,
        status: SwanPortableRestoreStatus
    ) -> SwanPortableRestoreResult {
        SwanPortableRestoreResult(
            canonicalHandle: verification.manifest.canonicalHandle,
            did: verification.manifest.did,
            fileCount: verification.manifest.files.count,
            includesPrivateKeys: false,
            manifestSHA256: verification.manifestSHA256,
            profileID: verification.manifest.profileID,
            stagingDirectory: dataDirectory
                .appending(path: "restore-staging", directoryHint: .isDirectory)
                .appending(path: manifestHash, directoryHint: .isDirectory)
                .path,
            status: status
        )
    }

    private func installIdentitySnapshotIfPresent(
        _ verification: SwanPortableArchiveVerification,
        archiveDescriptor: Int32
    ) async throws {
        guard let entry = verification.manifest.files.first(where: {
            $0.type == .identitySnapshot && $0.path == "identity/snapshot.json"
        }) else { return }
        guard let identitySnapshotInstaller else {
            throw SwanPortableExportError.invalidArchive
        }
        let data = try SwanPortableExportFilesystem.read(
            path: entry.path, root: archiveDescriptor, maximumBytes: 64 * 1_024
        )
        guard data.count == entry.byteCount,
              SwanPortableExportDigest.hex(data) == entry.sha256 else {
            throw SwanPortableExportError.invalidArchive
        }
        let snapshot = try SwanIdentitySnapshot.decode(data)
        try await identitySnapshotInstaller(snapshot.validatedForRestore(accountDID: verification.manifest.did))
    }
}
