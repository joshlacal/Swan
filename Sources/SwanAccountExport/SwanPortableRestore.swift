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

    public init() {
        afterRenameBeforeParentSync = nil
    }

    init(
        afterRenameBeforeParentSync: @escaping @Sendable () throws -> Void
    ) {
        self.afterRenameBeforeParentSync = afterRenameBeforeParentSync
    }

    public func stage(
        archiveAt inputDirectory: URL,
        dataDirectory: URL
    ) throws -> SwanPortableRestoreResult {
        let sourceDescriptor = try SwanPortableExportFilesystem.openArchiveRoot(
            inputDirectory
        )
        defer { _ = close(sourceDescriptor) }

        // The archive is fully authenticated before the Swan data directory is
        // opened, inspected, or changed.
        let preflight = try SwanPortableExportVerifier.verifySelfContainedArchive(
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
        var removeCreatedParentOnFailure = restoreParent.created
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
                let existing = try SwanPortableExportVerifier.verifySelfContainedArchive(
                    directoryDescriptor: existingDescriptor
                )
                try requireSameIdentity(existing, preflight)
                if restoreParent.created {
                    try SwanPortableExportFilesystem.synchronizeParent(dataDescriptor)
                }
                try SwanPortableExportFilesystem.requireCurrentOwnerOnlyDirectory(
                    canonicalDataDirectory,
                    matches: dataDescriptor
                )
                removeCreatedParentOnFailure = false
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
            var published = false
            do {
                try copyArchive(
                    preflight.manifest,
                    source: sourceDescriptor,
                    destination: stagingDescriptor
                )
                guard fsync(stagingDescriptor) == 0 else {
                    throw SwanPortableExportError.publicationFailed
                }
                let staged = try SwanPortableExportVerifier.verifySelfContainedArchive(
                    directoryDescriptor: stagingDescriptor
                )
                try requireSameIdentity(staged, preflight)
                try SwanPortableExportFilesystem.renameExclusively(
                    parent: restoreParent.descriptor,
                    source: temporaryName,
                    destination: manifestHash
                )
                published = true
                try afterRenameBeforeParentSync?()
                try SwanPortableExportFilesystem.synchronizeParent(
                    restoreParent.descriptor
                )
                if restoreParent.created {
                    try SwanPortableExportFilesystem.synchronizeParent(dataDescriptor)
                }
                try SwanPortableExportFilesystem.requireCurrentOwnerOnlyDirectory(
                    canonicalDataDirectory,
                    matches: dataDescriptor
                )
                let installedDescriptor =
                    try SwanPortableExportFilesystem.openOwnerOnlyDirectory(
                        parent: restoreParent.descriptor,
                        name: manifestHash
                    )
                _ = close(installedDescriptor)
                _ = close(stagingDescriptor)
                removeCreatedParentOnFailure = false
                return result(
                    verification: staged,
                    dataDirectory: canonicalDataDirectory,
                    manifestHash: manifestHash,
                    status: .staged
                )
            } catch {
                _ = close(stagingDescriptor)
                SwanPortableExportFilesystem.removeTree(
                    parent: restoreParent.descriptor,
                    name: published ? manifestHash : temporaryName
                )
                throw error
            }
        } catch {
            if removeCreatedParentOnFailure {
                SwanPortableExportFilesystem.removeEmptyDirectory(
                    parent: dataDescriptor,
                    name: "restore-staging"
                )
                try? SwanPortableExportFilesystem.synchronizeParent(dataDescriptor)
            }
            throw error
        }
    }

    private func copyArchive(
        _ manifest: SwanPortableExportManifest,
        source: Int32,
        destination: Int32
    ) throws {
        let manifestData = try SwanPortableExportFilesystem.read(
            path: "manifest.json",
            root: source,
            maximumBytes: 4 * 1_024 * 1_024
        )
        try SwanPortableExportFilesystem.write(
            manifestData,
            path: "manifest.json",
            root: destination
        )
        for entry in manifest.files {
            let maximumBytes = switch entry.type {
            case .plcHistory: 64 * 1_024
            default: SwanPortableExportFilesystem.maximumArtifactBytes
            }
            let data = try SwanPortableExportFilesystem.read(
                path: entry.path,
                root: source,
                maximumBytes: maximumBytes
            )
            try SwanPortableExportFilesystem.write(
                data,
                path: entry.path,
                root: destination
            )
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
}
