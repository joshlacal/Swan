import Crypto
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import PetrelCrypto
import PetrelPLC
import SwanAccounts
import SwanCore
import SwanSQLite
import SwanSpacesWire
import SwanStorage

/// The single safe failure exposed by the authenticated operator-backup
/// boundary. Cryptographic, archive, identity, and filesystem details remain
/// deliberately indistinguishable to callers.
public enum SwanOperatorAccountBackupError: Error, Sendable, Equatable {
    case failed
    /// The outer container authenticated successfully, but its encrypted
    /// plaintext predates mandatory PLC continuity preservation.
    case unsupportedVersion
}

enum SwanOperatorAccountBackupCompatibilityError: Error, Sendable, Equatable {
    case unsupportedEncryptedPayloadVersion
}

/// An opaque exact 256-bit key used only for operator backup encryption.
///
/// The value is intentionally non-Codable and has no printable
/// representation. It is never interchangeable with Swan's operator
/// authorization secret or account-envelope KEK.
public struct SwanOperatorBackupKey: Sendable {
    let bytes: Data

    init(rawBytes: Data) throws {
        guard rawBytes.count == 32 else {
            throw SwanOperatorAccountBackupError.failed
        }
        bytes = rawBytes
    }

    public init(secretFile: URL) throws {
        do {
            try self.init(rawBytes: Self.readMountedKey(secretFile))
        } catch {
            throw SwanOperatorAccountBackupError.failed
        }
    }

    private static func readMountedKey(_ url: URL) throws -> Data {
        let descriptor = url.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else { throw SwanOperatorAccountBackupError.failed }
        defer { _ = close(descriptor) }

        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              (metadata.st_mode & 0o777) == 0o600,
              metadata.st_size > 0,
              metadata.st_size <= 45 else {
            throw SwanOperatorAccountBackupError.failed
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        var encoded = try handle.read(upToCount: 46) ?? Data()
        guard encoded.count <= 45 else { throw SwanOperatorAccountBackupError.failed }
        if encoded.last == 0x0A {
            encoded.removeLast()
            if encoded.last == 0x0D { encoded.removeLast() }
        }
        guard encoded.count == 43,
              let text = String(data: encoded, encoding: .utf8),
              text.utf8.allSatisfy({
                  ($0 >= 0x41 && $0 <= 0x5a)
                      || ($0 >= 0x61 && $0 <= 0x7a)
                      || ($0 >= 0x30 && $0 <= 0x39)
                      || $0 == 0x2d || $0 == 0x5f
              }),
              let decoded = SwanOperatorBackupBase64URL.decode(text),
              decoded.count == 32,
              SwanOperatorBackupBase64URL.encode(decoded) == text else {
            throw SwanOperatorAccountBackupError.failed
        }
        return decoded
    }
}

struct SwanOperatorAccountBackupManifest: Codable, Sendable, Equatable {
    static let formatValue = "swan-operator-account-backup-v1"
    static let cipherValue = "AES-256-GCM"
    static let envelopePathValue = "operator/secrets.aesgcm"

    let cipher: String
    let envelopePath: String
    let envelopeSHA256: String
    let format: String
    let portableManifestSHA256: String
    let profileID: String

    init(portableManifestSHA256: String, envelopeSHA256: String) throws {
        guard portableManifestSHA256.hasPrefix("sha256:"),
              SwanPortableExportDigest.isCanonicalHex(
                  String(portableManifestSHA256.dropFirst("sha256:".count))
              ),
              SwanPortableExportDigest.isCanonicalHex(envelopeSHA256) else {
            throw SwanOperatorAccountBackupError.failed
        }
        cipher = Self.cipherValue
        envelopePath = Self.envelopePathValue
        self.envelopeSHA256 = envelopeSHA256
        format = Self.formatValue
        self.portableManifestSHA256 = portableManifestSHA256
        profileID = PermissionedData0016.profileID
    }
}

enum SwanOperatorAccountBackupManifestCodec {
    private static let keys = Set([
        "cipher", "envelopePath", "envelopeSHA256", "format",
        "portableManifestSHA256", "profileID",
    ])

    static func encode(_ manifest: SwanOperatorAccountBackupManifest) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(manifest)
    }

    static func decode(_ data: Data) throws -> SwanOperatorAccountBackupManifest {
        guard !data.isEmpty, data.count <= 4 * 1_024,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == keys,
              object["format"] as? String == SwanOperatorAccountBackupManifest.formatValue,
              object["profileID"] as? String == PermissionedData0016.profileID,
              object["envelopePath"] as? String
                == SwanOperatorAccountBackupManifest.envelopePathValue,
              object["cipher"] as? String == SwanOperatorAccountBackupManifest.cipherValue else {
            throw SwanOperatorAccountBackupError.failed
        }
        let decoded: SwanOperatorAccountBackupManifest
        do {
            let wire = try JSONDecoder().decode(
                SwanOperatorAccountBackupManifest.self,
                from: data
            )
            decoded = try SwanOperatorAccountBackupManifest(
                portableManifestSHA256: wire.portableManifestSHA256,
                envelopeSHA256: wire.envelopeSHA256
            )
        } catch {
            throw SwanOperatorAccountBackupError.failed
        }
        guard try encode(decoded) == data else {
            throw SwanOperatorAccountBackupError.failed
        }
        return decoded
    }
}

/// Public, secret-free result returned after a newly published backup has
/// been independently verified.
public struct SwanOperatorAccountBackupResult: Codable, Sendable, Equatable {
    public let backupManifestSHA256: String
    public let containsEncryptedPrivateKeys: Bool
    public let did: String
    public let fileCount: Int
    public let outputDirectory: String
    public let portableManifestSHA256: String
}

/// Public verification metadata. The password verifier, key references,
/// private scalars, envelope plaintext, and backup key are not representable.
public struct SwanOperatorAccountBackupVerification: Sendable, Equatable {
    public let backupManifestSHA256: String
    public let canonicalHandle: String
    public let did: String
    public let fileCount: Int
    public let portableManifestSHA256: String
    public let profileID: String
    public let publicGenesisCommitCID: String
}

/// Module-internal authenticated plaintext transport used only by the
/// offline restorer. No public result or error can represent these fields.
struct SwanOperatorVerifiedBackupPayload: Sendable {
    let verification: SwanOperatorAccountBackupVerification
    let portable: SwanPortableArchiveVerification
    let secrets: SwanOperatorAccountSecrets
}

/// Creates a single-account same-version operator backup without mutating its
/// control row, repository database, blob inventory, or key store.
public struct SwanOperatorAccountBackupExporter: Sendable {
    private let database: SQLiteAccountDatabase
    private let keyReader: any AccountKeyMaterialReader
    private let continuityInventory:
        @Sendable () async throws -> PLCCredentialKeyContinuityInventory
    private let now: @Sendable () -> Date
    private let afterRenameBeforeParentSync: (@Sendable () throws -> Void)?

    public init(
        database: SQLiteAccountDatabase,
        keyReader: any AccountKeyMaterialReader,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.database = database
        self.keyReader = keyReader
        continuityInventory = {
            try await database
                .operatorBackupPLCCredentialKeyContinuityInventory()
        }
        self.now = now
        afterRenameBeforeParentSync = nil
    }

    init(
        database: SQLiteAccountDatabase,
        keyReader: any AccountKeyMaterialReader,
        now: @escaping @Sendable () -> Date = Date.init,
        continuityInventory: @escaping @Sendable () async throws
            -> PLCCredentialKeyContinuityInventory,
        afterRenameBeforeParentSync: @escaping @Sendable () throws -> Void
    ) {
        self.database = database
        self.keyReader = keyReader
        self.continuityInventory = continuityInventory
        self.now = now
        self.afterRenameBeforeParentSync = afterRenameBeforeParentSync
    }

    /// Explicit synthetic-fixture hook. Production construction always reads
    /// the companion control database and fails closed when it is unavailable.
    init(
        database: SQLiteAccountDatabase,
        keyReader: any AccountKeyMaterialReader,
        now: @escaping @Sendable () -> Date = Date.init,
        continuityInventory: @escaping @Sendable () async throws
            -> PLCCredentialKeyContinuityInventory
    ) {
        self.database = database
        self.keyReader = keyReader
        self.continuityInventory = continuityInventory
        self.now = now
        afterRenameBeforeParentSync = nil
    }

    public func backup(
        account: AccountControlAccount,
        credential: AccountControlCredential,
        using backupKey: SwanOperatorBackupKey,
        to outputDirectory: URL
    ) async throws -> SwanOperatorAccountBackupResult {
        do {
            let destination = try SwanPortableExportDestination(outputDirectory)
            return try await backup(
                account: account,
                credential: credential,
                using: backupKey,
                to: destination
            )
        } catch {
            throw SwanOperatorAccountBackupError.failed
        }
    }

    public func backup(
        account: AccountControlAccount,
        credential: AccountControlCredential,
        using backupKey: SwanOperatorBackupKey,
        to destination: SwanPortableExportDestination
    ) async throws -> SwanOperatorAccountBackupResult {
        do {
            return try await performBackup(
                account: account,
                credential: credential,
                using: backupKey,
                to: destination
            )
        } catch {
            throw SwanOperatorAccountBackupError.failed
        }
    }

    private func performBackup(
        account: AccountControlAccount,
        credential: AccountControlCredential,
        using backupKey: SwanOperatorBackupKey,
        to destination: SwanPortableExportDestination
    ) async throws -> SwanOperatorAccountBackupResult {
        guard account.status == .active,
              credential.did == account.did,
              credential.updatedAt == account.updatedAt,
              account.credentialState == .configured,
              let signingControlReference = account.signingKey,
              let rotationControlReference = account.rotationKey,
              signingControlReference.purpose == .signing,
              rotationControlReference.purpose == .rotation,
              signingControlReference.generation
                == SwanOperatorAccountSecrets.supportedKeyGeneration,
              rotationControlReference.generation
                == SwanOperatorAccountSecrets.supportedKeyGeneration,
              let publicGenesisCommitCID = account.publicGenesisCommitCID else {
            throw SwanOperatorAccountBackupError.failed
        }
        let signingReference = try AccountKeyReference(
            accountDID: account.did,
            purpose: .signing,
            generation: signingControlReference.generation
        )
        let rotationReference = try AccountKeyReference(
            accountDID: account.did,
            purpose: .rotation,
            generation: rotationControlReference.generation
        )
        let signingScalar = try await keyReader.key(for: signingReference)
        let rotationScalar = try await keyReader.key(for: rotationReference)
        let continuityInventory = try await self.continuityInventory()
        let secrets = try SwanOperatorAccountSecrets(
            profileID: PermissionedData0016.profileID,
            portableManifestSHA256: "",
            did: account.did,
            canonicalHandle: account.canonicalHandle,
            passwordVerifier: credential.verifier,
            publicGenesisCommitCID: publicGenesisCommitCID,
            signingKeyReference: signingControlReference,
            rotationKeyReference: rotationControlReference,
            signingPrivateScalar: signingScalar,
            rotationPrivateScalar: rotationScalar,
            plcCredentialKeyContinuity: continuityInventory,
            allowDeferredDigest: true
        )

        let stagingName = ".swan-backup-\(UUID().uuidString.lowercased())"
        let stagingDescriptor = try SwanPortableExportFilesystem.createStagingDirectory(
            parent: destination.parentDescriptor,
            name: stagingName
        )
        do {
            let stagingURL = destination.url.deletingLastPathComponent()
                .appending(path: stagingName, directoryHint: .isDirectory)
            let portableURL = stagingURL.appending(path: "portable", directoryHint: .isDirectory)
            let portableDestination = try SwanPortableExportDestination(portableURL)
            let portable = try await SwanPortableAccountExporter(
                database: database,
                keyStore: keyReader,
                now: now
            ).export(account: account, to: portableDestination)

            let boundSecrets = try secrets.binding(
                portableManifestSHA256: portable.manifestSHA256
            )
            let plaintext = try SwanOperatorAccountSecretsCodec.encode(boundSecrets)
            let sealed = try AES.GCM.seal(
                plaintext,
                using: SymmetricKey(data: backupKey.bytes),
                authenticating: SwanOperatorAccountBackupAAD.make(
                    portableManifestSHA256: portable.manifestSHA256
                )
            )
            guard let envelope = sealed.combined else {
                throw SwanOperatorAccountBackupError.failed
            }
            try SwanPortableExportFilesystem.write(
                envelope,
                path: SwanOperatorAccountBackupManifest.envelopePathValue,
                root: stagingDescriptor
            )
            let manifest = try SwanOperatorAccountBackupManifest(
                portableManifestSHA256: portable.manifestSHA256,
                envelopeSHA256: SwanPortableExportDigest.hex(envelope)
            )
            let manifestData = try SwanOperatorAccountBackupManifestCodec.encode(manifest)
            try SwanPortableExportFilesystem.write(
                manifestData,
                path: "manifest.json",
                root: stagingDescriptor
            )
            guard fsync(stagingDescriptor) == 0 else {
                throw SwanOperatorAccountBackupError.failed
            }
            let staged = try await SwanOperatorAccountBackupVerifier
                .verifiedPayloadStreaming(
                directoryDescriptor: stagingDescriptor,
                using: backupKey
            ).verification
            try destination.requireCurrentParentAndAbsentTarget()
            try Task.checkCancellation()
            try SwanPortableExportFilesystem.renameExclusively(
                parent: destination.parentDescriptor,
                source: stagingName,
                destination: destination.outputName
            )
            try afterRenameBeforeParentSync?()
            try SwanPortableExportFilesystem.synchronizeParent(destination.parentDescriptor)
            try destination.requireCurrentParentAndInstalledTarget()
            guard try SwanPortableExportFilesystem.currentChildDirectoryMatches(
                parent: destination.parentDescriptor,
                name: destination.outputName,
                expectedDescriptor: stagingDescriptor
            ) else {
                throw SwanOperatorAccountBackupError.failed
            }
            let installed = try await SwanOperatorAccountBackupVerifier
                .verifiedPayloadStreaming(
                directoryDescriptor: stagingDescriptor,
                using: backupKey
            ).verification
            guard installed == staged,
                  try SwanPortableExportFilesystem.currentChildDirectoryMatches(
                      parent: destination.parentDescriptor,
                      name: destination.outputName,
                      expectedDescriptor: stagingDescriptor
                  ) else {
                throw SwanOperatorAccountBackupError.failed
            }
            _ = close(stagingDescriptor)
            return SwanOperatorAccountBackupResult(
                backupManifestSHA256: installed.backupManifestSHA256,
                containsEncryptedPrivateKeys: true,
                did: installed.did,
                fileCount: installed.fileCount,
                outputDirectory: destination.url.path,
                portableManifestSHA256: installed.portableManifestSHA256
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
                throw SwanOperatorAccountBackupError.failed
            }
            _ = close(stagingDescriptor)
            throw SwanOperatorAccountBackupError.failed
        }
    }
}

public enum SwanOperatorAccountBackupVerifier {
    public static func verifyBackup(
        at root: URL,
        using backupKey: SwanOperatorBackupKey
    ) throws -> SwanOperatorAccountBackupVerification {
        do {
            let descriptor = try SwanPortableExportFilesystem.openArchiveRoot(root)
            defer { _ = close(descriptor) }
            return try verify(directoryDescriptor: descriptor, using: backupKey)
        } catch is SwanOperatorAccountBackupCompatibilityError {
            throw SwanOperatorAccountBackupError.unsupportedVersion
        } catch {
            throw SwanOperatorAccountBackupError.failed
        }
    }

    public static func verifyBackupStreaming(
        at root: URL,
        using backupKey: SwanOperatorBackupKey
    ) async throws -> SwanOperatorAccountBackupVerification {
        do {
            let descriptor = try SwanPortableExportFilesystem.openArchiveRoot(root)
            defer { _ = close(descriptor) }
            return try await verifiedPayloadStreaming(
                directoryDescriptor: descriptor,
                using: backupKey
            ).verification
        } catch is SwanOperatorAccountBackupCompatibilityError {
            throw SwanOperatorAccountBackupError.unsupportedVersion
        } catch {
            throw SwanOperatorAccountBackupError.failed
        }
    }

    static func verify(
        directoryDescriptor root: Int32,
        using backupKey: SwanOperatorBackupKey
    ) throws -> SwanOperatorAccountBackupVerification {
        try verifiedPayload(
            directoryDescriptor: root,
            using: backupKey
        ).verification
    }

    static func verifiedPayload(
        directoryDescriptor root: Int32,
        using backupKey: SwanOperatorBackupKey
    ) throws -> SwanOperatorVerifiedBackupPayload {
        do {
            try SwanPortableExportFilesystem.requireOwnerOnlyDirectory(root)
            let manifestData = try SwanPortableExportFilesystem.read(
                path: "manifest.json",
                root: root,
                maximumBytes: 4 * 1_024
            )
            let manifest = try SwanOperatorAccountBackupManifestCodec.decode(manifestData)
            let portableDescriptor = try SwanPortableExportFilesystem.openOwnerOnlyDirectory(
                parent: root,
                name: "portable"
            )
            defer { _ = close(portableDescriptor) }
            let portable = try SwanPortableExportVerifier.verifySelfContainedArchive(
                directoryDescriptor: portableDescriptor
            )
            guard portable.manifestSHA256 == manifest.portableManifestSHA256,
                  portable.manifest.profileID == manifest.profileID,
                  portable.manifest.includesPrivateKeys == false else {
                throw SwanOperatorAccountBackupError.failed
            }
            let envelope = try SwanPortableExportFilesystem.read(
                path: manifest.envelopePath,
                root: root,
                maximumBytes:
                    SwanOperatorAccountSecretsCodec.maximumEncodedBytes + 64
            )
            guard SwanPortableExportDigest.hex(envelope) == manifest.envelopeSHA256 else {
                throw SwanOperatorAccountBackupError.failed
            }
            let plaintext: Data
            do {
                plaintext = try AES.GCM.open(
                    AES.GCM.SealedBox(combined: envelope),
                    using: SymmetricKey(data: backupKey.bytes),
                    authenticating: SwanOperatorAccountBackupAAD.make(
                        portableManifestSHA256: manifest.portableManifestSHA256
                    )
                )
            } catch {
                throw SwanOperatorAccountBackupError.failed
            }
            let secrets = try SwanOperatorAccountSecretsCodec.decode(plaintext)
            let plc = try SwanOperatorPortablePLC.read(from: portableDescriptor)
            try validate(
                secrets: secrets,
                portable: portable,
                plc: plc,
                manifest: manifest
            )

            let portableExpectedPaths = Set(
                portable.manifest.files.map(\.path) + ["manifest.json"]
            )
            let portableExpectedDirectories = try SwanPortableExportFilesystem
                .expectedDirectories(for: portableExpectedPaths)
            let portableEntries = try SwanPortableExportFilesystem.entries(
                root: portableDescriptor,
                maximumEntries: portableExpectedPaths.count
                    + portableExpectedDirectories.count
            )
            let expectedFiles = Set([
                "manifest.json",
                SwanOperatorAccountBackupManifest.envelopePathValue,
            ] + portableEntries.files.map { "portable/\($0)" })
            let expectedDirectories = try SwanPortableExportFilesystem.expectedDirectories(
                for: expectedFiles
            )
            let entries = try SwanPortableExportFilesystem.entries(
                root: root,
                maximumEntries: expectedFiles.count + expectedDirectories.count
            )
            guard entries.files == expectedFiles,
                  entries.directories == expectedDirectories else {
                throw SwanOperatorAccountBackupError.failed
            }
            let verification = SwanOperatorAccountBackupVerification(
                backupManifestSHA256:
                    "sha256:\(SwanPortableExportDigest.hex(manifestData))",
                canonicalHandle: portable.manifest.canonicalHandle,
                did: portable.manifest.did,
                fileCount: entries.files.count,
                portableManifestSHA256: portable.manifestSHA256,
                profileID: portable.manifest.profileID,
                publicGenesisCommitCID: plc.publicGenesisCommitCID
            )
            return SwanOperatorVerifiedBackupPayload(
                verification: verification,
                portable: portable,
                secrets: secrets
            )
        } catch let error as SwanOperatorAccountBackupCompatibilityError {
            throw error
        } catch {
            throw SwanOperatorAccountBackupError.failed
        }
    }

    static func verifiedPayloadStreaming(
        directoryDescriptor root: Int32,
        using backupKey: SwanOperatorBackupKey
    ) async throws -> SwanOperatorVerifiedBackupPayload {
        do {
            try SwanPortableExportFilesystem.requireOwnerOnlyDirectory(root)
            let manifestData = try SwanPortableExportFilesystem.read(
                path: "manifest.json",
                root: root,
                maximumBytes: 4 * 1_024
            )
            let manifest = try SwanOperatorAccountBackupManifestCodec.decode(manifestData)
            let portableDescriptor = try SwanPortableExportFilesystem
                .openOwnerOnlyDirectory(parent: root, name: "portable")
            defer { _ = close(portableDescriptor) }
            let portable = try await SwanPortableExportVerifier
                .verifySelfContainedArchiveStreaming(
                    directoryDescriptor: portableDescriptor
                )
            guard portable.manifestSHA256 == manifest.portableManifestSHA256,
                  portable.manifest.profileID == manifest.profileID,
                  portable.manifest.includesPrivateKeys == false else {
                throw SwanOperatorAccountBackupError.failed
            }
            let envelope = try SwanPortableExportFilesystem.read(
                path: manifest.envelopePath,
                root: root,
                maximumBytes:
                    SwanOperatorAccountSecretsCodec.maximumEncodedBytes + 64
            )
            guard SwanPortableExportDigest.hex(envelope)
                    == manifest.envelopeSHA256 else {
                throw SwanOperatorAccountBackupError.failed
            }
            let plaintext: Data
            do {
                plaintext = try AES.GCM.open(
                    AES.GCM.SealedBox(combined: envelope),
                    using: SymmetricKey(data: backupKey.bytes),
                    authenticating: SwanOperatorAccountBackupAAD.make(
                        portableManifestSHA256: manifest.portableManifestSHA256
                    )
                )
            } catch {
                throw SwanOperatorAccountBackupError.failed
            }
            let secrets = try SwanOperatorAccountSecretsCodec.decode(plaintext)
            let plc = try SwanOperatorPortablePLC.read(from: portableDescriptor)
            try validate(
                secrets: secrets,
                portable: portable,
                plc: plc,
                manifest: manifest
            )
            let portableExpectedPaths = Set(
                portable.manifest.files.map(\.path) + ["manifest.json"]
            )
            let portableExpectedDirectories = try SwanPortableExportFilesystem
                .expectedDirectories(for: portableExpectedPaths)
            let portableEntries = try SwanPortableExportFilesystem.entries(
                root: portableDescriptor,
                maximumEntries: portableExpectedPaths.count
                    + portableExpectedDirectories.count
            )
            let expectedFiles = Set([
                "manifest.json",
                SwanOperatorAccountBackupManifest.envelopePathValue,
            ] + portableEntries.files.map { "portable/\($0)" })
            let expectedDirectories = try SwanPortableExportFilesystem
                .expectedDirectories(for: expectedFiles)
            let entries = try SwanPortableExportFilesystem.entries(
                root: root,
                maximumEntries: expectedFiles.count + expectedDirectories.count
            )
            guard entries.files == expectedFiles,
                  entries.directories == expectedDirectories else {
                throw SwanOperatorAccountBackupError.failed
            }
            let verification = SwanOperatorAccountBackupVerification(
                backupManifestSHA256:
                    "sha256:\(SwanPortableExportDigest.hex(manifestData))",
                canonicalHandle: portable.manifest.canonicalHandle,
                did: portable.manifest.did,
                fileCount: entries.files.count,
                portableManifestSHA256: portable.manifestSHA256,
                profileID: portable.manifest.profileID,
                publicGenesisCommitCID: plc.publicGenesisCommitCID
            )
            return SwanOperatorVerifiedBackupPayload(
                verification: verification,
                portable: portable,
                secrets: secrets
            )
        } catch let error as SwanOperatorAccountBackupCompatibilityError {
            throw error
        } catch {
            throw SwanOperatorAccountBackupError.failed
        }
    }

    private static func validate(
        secrets: SwanOperatorAccountSecrets,
        portable: SwanPortableArchiveVerification,
        plc: SwanOperatorPortablePLC,
        manifest: SwanOperatorAccountBackupManifest
    ) throws {
        guard secrets.profileID == manifest.profileID,
              secrets.portableManifestSHA256 == portable.manifestSHA256,
              secrets.did == portable.manifest.did,
              secrets.canonicalHandle == portable.manifest.canonicalHandle,
              secrets.publicGenesisCommitCID == plc.publicGenesisCommitCID,
              secrets.did == plc.did,
              secrets.signingKeyReference.purpose == .signing,
              secrets.rotationKeyReference.purpose == .rotation,
              secrets.signingKeyReference.generation
                == SwanOperatorAccountSecrets.supportedKeyGeneration,
              secrets.rotationKeyReference.generation
                == SwanOperatorAccountSecrets.supportedKeyGeneration else {
            throw SwanOperatorAccountBackupError.failed
        }
        _ = try AccountControlCredential(
            did: secrets.did,
            verifier: secrets.passwordVerifier,
            updatedAt: Date(timeIntervalSince1970: 0)
        )
        let signingKey = try P256.Signing.PrivateKey(
            rawRepresentation: secrets.signingPrivateScalar
        )
        let rotationKey = try P256.Signing.PrivateKey(
            rawRepresentation: secrets.rotationPrivateScalar
        )
        guard signingKey.publicKey.compressedRepresentation
                == portable.signingPublicKey.compressedRepresentation,
              plc.signingDIDKey == P256DIDKey(publicKey: signingKey.publicKey).value,
              plc.rotationDIDKey == P256DIDKey(publicKey: rotationKey.publicKey).value else {
            throw SwanOperatorAccountBackupError.failed
        }
    }
}

/// Plaintext secret material remains module-internal, non-Codable, and has no
/// description/debug representation.
struct SwanOperatorAccountSecrets: Sendable {
    /// The pinned alpha portable archive carries the genesis PLC operation,
    /// so generation one is the only key generation it can independently
    /// authenticate. A later format must add an authenticated rotation fact
    /// before accepting current references above generation one.
    static let supportedKeyGeneration: UInt64 = 1

    let profileID: String
    let portableManifestSHA256: String
    let did: String
    let canonicalHandle: String
    let passwordVerifier: String
    let publicGenesisCommitCID: String
    let signingKeyReference: AccountControlKeyReference
    let rotationKeyReference: AccountControlKeyReference
    let signingPrivateScalar: Data
    let rotationPrivateScalar: Data
    let plcCredentialKeyContinuity: PLCCredentialKeyContinuityInventory

    init(
        profileID: String,
        portableManifestSHA256: String,
        did: String,
        canonicalHandle: String,
        passwordVerifier: String,
        publicGenesisCommitCID: String,
        signingKeyReference: AccountControlKeyReference,
        rotationKeyReference: AccountControlKeyReference,
        signingPrivateScalar: Data,
        rotationPrivateScalar: Data,
        plcCredentialKeyContinuity: PLCCredentialKeyContinuityInventory,
        allowDeferredDigest: Bool = false
    ) throws {
        guard profileID == PermissionedData0016.profileID,
              allowDeferredDigest || portableManifestSHA256.hasPrefix("sha256:"),
              allowDeferredDigest
                || SwanPortableExportDigest.isCanonicalHex(
                    String(portableManifestSHA256.dropFirst("sha256:".count))
                ),
              try AccountIdentifiers.validateDID(did) == did,
              try AccountIdentifiers.canonicalHandle(canonicalHandle) == canonicalHandle,
              AccountControlIdentifiers.isPublicGenesisCommitCID(publicGenesisCommitCID),
              signingKeyReference.purpose == .signing,
              rotationKeyReference.purpose == .rotation,
              signingKeyReference.generation == Self.supportedKeyGeneration,
              rotationKeyReference.generation == Self.supportedKeyGeneration,
              signingPrivateScalar.count == 32,
              rotationPrivateScalar.count == 32 else {
            throw SwanOperatorAccountBackupError.failed
        }
        _ = try AccountControlCredential(
            did: did,
            verifier: passwordVerifier,
            updatedAt: Date(timeIntervalSince1970: 0)
        )
        self.profileID = profileID
        self.portableManifestSHA256 = portableManifestSHA256
        self.did = did
        self.canonicalHandle = canonicalHandle
        self.passwordVerifier = passwordVerifier
        self.publicGenesisCommitCID = publicGenesisCommitCID
        self.signingKeyReference = signingKeyReference
        self.rotationKeyReference = rotationKeyReference
        self.signingPrivateScalar = signingPrivateScalar
        self.rotationPrivateScalar = rotationPrivateScalar
        self.plcCredentialKeyContinuity = plcCredentialKeyContinuity
    }

    func binding(portableManifestSHA256: String) throws -> Self {
        try Self(
            profileID: profileID,
            portableManifestSHA256: portableManifestSHA256,
            did: did,
            canonicalHandle: canonicalHandle,
            passwordVerifier: passwordVerifier,
            publicGenesisCommitCID: publicGenesisCommitCID,
            signingKeyReference: signingKeyReference,
            rotationKeyReference: rotationKeyReference,
            signingPrivateScalar: signingPrivateScalar,
            rotationPrivateScalar: rotationPrivateScalar,
            plcCredentialKeyContinuity: plcCredentialKeyContinuity
        )
    }
}

private enum SwanOperatorAccountSecretsCodec {
    static let formatValue = "swan-operator-account-secrets-v2"
    static let legacyFormatValue = "swan-operator-account-secrets-v1"
    static let maximumEncodedBytes =
        PLCCredentialKeyContinuityInventory.maximumCheckpointBytes
            + 16 * 1_024
    private static let rootKeys = Set([
        "canonicalHandle", "did", "format", "passwordVerifier",
        "plcCredentialKeyContinuity",
        "portableManifestSHA256", "profileID", "publicGenesisCommitCID",
        "rotationKeyReference", "rotationPrivateScalar",
        "signingKeyReference", "signingPrivateScalar",
    ])
    private static let referenceKeys = Set(["generation", "purpose", "reference"])
    private static let continuityKeys = Set(["issuer", "terminalCID"])

    static func encode(_ secrets: SwanOperatorAccountSecrets) throws -> Data {
        let object: [String: Any] = [
            "canonicalHandle": secrets.canonicalHandle,
            "did": secrets.did,
            "format": formatValue,
            "passwordVerifier": secrets.passwordVerifier,
            "plcCredentialKeyContinuity":
                try continuityObject(secrets.plcCredentialKeyContinuity),
            "portableManifestSHA256": secrets.portableManifestSHA256,
            "profileID": secrets.profileID,
            "publicGenesisCommitCID": secrets.publicGenesisCommitCID,
            "rotationKeyReference": referenceObject(secrets.rotationKeyReference),
            "rotationPrivateScalar": SwanOperatorBackupBase64URL.encode(
                secrets.rotationPrivateScalar
            ),
            "signingKeyReference": referenceObject(secrets.signingKeyReference),
            "signingPrivateScalar": SwanOperatorBackupBase64URL.encode(
                secrets.signingPrivateScalar
            ),
        ]
        do {
            let data = try JSONSerialization.data(
                withJSONObject: object,
                options: [.sortedKeys, .withoutEscapingSlashes]
            )
            guard data.count <= maximumEncodedBytes else {
                throw SwanOperatorAccountBackupError.failed
            }
            return data
        } catch {
            throw SwanOperatorAccountBackupError.failed
        }
    }

    static func decode(_ data: Data) throws -> SwanOperatorAccountSecrets {
        guard !data.isEmpty, data.count <= maximumEncodedBytes,
              let object =
                  try JSONSerialization.jsonObject(with: data)
                    as? [String: Any],
              let encodedFormat = object["format"] as? String else {
            throw SwanOperatorAccountBackupError.failed
        }
        if encodedFormat == legacyFormatValue {
            throw SwanOperatorAccountBackupCompatibilityError
                .unsupportedEncryptedPayloadVersion
        }
        guard
              Set(object.keys) == rootKeys,
              encodedFormat == formatValue,
              let canonicalHandle = object["canonicalHandle"] as? String,
              let did = object["did"] as? String,
              let passwordVerifier = object["passwordVerifier"] as? String,
              let continuityRows =
                  object["plcCredentialKeyContinuity"] as? [[String: Any]],
              let portableManifestSHA256 = object["portableManifestSHA256"] as? String,
              let profileID = object["profileID"] as? String,
              let publicGenesisCommitCID = object["publicGenesisCommitCID"] as? String,
              let rotationScalarText = object["rotationPrivateScalar"] as? String,
              let signingScalarText = object["signingPrivateScalar"] as? String,
              let rotationReferenceObject =
                object["rotationKeyReference"] as? [String: Any],
              Set(rotationReferenceObject.keys) == referenceKeys,
              let signingReferenceObject =
                object["signingKeyReference"] as? [String: Any],
              Set(signingReferenceObject.keys) == referenceKeys else {
            throw SwanOperatorAccountBackupError.failed
        }
        guard let signing = SwanOperatorBackupBase64URL.decode(
                  signingScalarText
              ),
              let rotation = SwanOperatorBackupBase64URL.decode(
                  rotationScalarText
              ),
              SwanOperatorBackupBase64URL.encode(signing) == signingScalarText,
              SwanOperatorBackupBase64URL.encode(rotation) == rotationScalarText else {
            throw SwanOperatorAccountBackupError.failed
        }
        let signingReference = try decodeReference(signingReferenceObject)
        let rotationReference = try decodeReference(rotationReferenceObject)
        let continuity = try decodeContinuity(continuityRows)
        let secrets = try SwanOperatorAccountSecrets(
            profileID: profileID,
            portableManifestSHA256: portableManifestSHA256,
            did: did,
            canonicalHandle: canonicalHandle,
            passwordVerifier: passwordVerifier,
            publicGenesisCommitCID: publicGenesisCommitCID,
            signingKeyReference: signingReference,
            rotationKeyReference: rotationReference,
            signingPrivateScalar: signing,
            rotationPrivateScalar: rotation,
            plcCredentialKeyContinuity: continuity
        )
        guard try encode(secrets) == data else {
            throw SwanOperatorAccountBackupError.failed
        }
        return secrets
    }

    private static func continuityObject(
        _ inventory: PLCCredentialKeyContinuityInventory
    ) throws -> [[String: String]] {
        let object = inventory.checkpoints.map {
            ["issuer": $0.issuer, "terminalCID": $0.terminalCID]
        }
        let data = try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        guard
            data.count
                <= PLCCredentialKeyContinuityInventory
                    .maximumCheckpointBytes
        else {
            throw SwanOperatorAccountBackupError.failed
        }
        return object
    }

    private static func decodeContinuity(
        _ rows: [[String: Any]]
    ) throws -> PLCCredentialKeyContinuityInventory {
        guard
            rows.count
                <= PLCCredentialKeyContinuityInventory
                    .maximumCheckpointCount
        else {
            throw SwanOperatorAccountBackupError.failed
        }
        let encoded = try JSONSerialization.data(
            withJSONObject: rows,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        guard
            encoded.count
                <= PLCCredentialKeyContinuityInventory
                    .maximumCheckpointBytes
        else {
            throw SwanOperatorAccountBackupError.failed
        }
        let checkpoints = try rows.map { row in
            guard Set(row.keys) == continuityKeys,
                  let issuer = row["issuer"] as? String,
                  let terminalCID = row["terminalCID"] as? String else {
                throw SwanOperatorAccountBackupError.failed
            }
            return try PLCCredentialKeyContinuityCheckpoint(
                issuer: issuer,
                terminalCID: terminalCID
            )
        }
        let inventory = try PLCCredentialKeyContinuityInventory(
            checkpoints: checkpoints
        )
        guard inventory.checkpoints == checkpoints else {
            throw SwanOperatorAccountBackupError.failed
        }
        return inventory
    }

    private static func referenceObject(
        _ reference: AccountControlKeyReference
    ) -> [String: Any] {
        [
            "generation": reference.generation,
            "purpose": reference.purpose.rawValue,
            "reference": reference.reference,
        ]
    }

    private static func decodeReference(
        _ object: [String: Any]
    ) throws -> AccountControlKeyReference {
        guard Set(object.keys) == referenceKeys,
              let purposeText = object["purpose"] as? String,
              let purpose = AccountControlKeyReference.Purpose(rawValue: purposeText),
              let reference = object["reference"] as? String,
              let generationValue = object["generation"],
              let generationNumber = generationValue as? NSNumber,
              let generation = UInt64(generationNumber.stringValue) else {
            throw SwanOperatorAccountBackupError.failed
        }
        do {
            return try AccountControlKeyReference(
                purpose: purpose,
                generation: generation,
                reference: reference
            )
        } catch {
            throw SwanOperatorAccountBackupError.failed
        }
    }
}

private struct SwanOperatorPortablePLC {
    let did: String
    let publicGenesisCommitCID: String
    let signingDIDKey: String
    let rotationDIDKey: String

    static func read(from portableRoot: Int32) throws -> Self {
        let data = try SwanPortableExportFilesystem.read(
            path: "plc/history.json",
            root: portableRoot,
            maximumBytes: 64 * 1_024
        )
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let did = object["did"] as? String,
              let publicGenesisCommitCID = object["publicGenesisCommitCID"] as? String,
              let operationObject = object["operation"] else {
            throw SwanOperatorAccountBackupError.failed
        }
        let operationData = try JSONSerialization.data(
            withJSONObject: operationObject,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let operation = try PLCOperationCodec.decodeSignedJSON(operationData)
        try PLCOperationCodec.verifyGenesis(operation, expectedDID: did)
        guard let regular = operation.regular,
              regular.rotationKeys.count == 1,
              let signingDIDKey = regular.verificationMethods["atproto"] else {
            throw SwanOperatorAccountBackupError.failed
        }
        return Self(
            did: did,
            publicGenesisCommitCID: publicGenesisCommitCID,
            signingDIDKey: signingDIDKey,
            rotationDIDKey: regular.rotationKeys[0]
        )
    }
}

private enum SwanOperatorAccountBackupAAD {
    static func make(portableManifestSHA256: String) -> Data {
        Data(
            [
                SwanOperatorAccountBackupManifest.formatValue,
                PermissionedData0016.profileID,
                portableManifestSHA256,
            ].joined(separator: "\u{0}").utf8
        )
    }
}

private enum SwanOperatorBackupBase64URL {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func decode(_ text: String) -> Data? {
        var base64 = text
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64.append(String(repeating: "=", count: (4 - base64.count % 4) % 4))
        return Data(base64Encoded: base64)
    }
}
