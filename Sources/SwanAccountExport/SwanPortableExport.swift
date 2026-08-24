import Crypto
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import Petrel
import SwanAccounts
import SwanCore
import PetrelRepo
import SwanSQLite
import SwanSpaces
import SwanSpacesWire
import SwanStorage

public enum SwanPortableExportFileType: String, Codable, Sendable, CaseIterable {
    case publicCAR = "public-car"
    case spaceCAR = "space-car"
    case publicBlob = "public-blob"
    case spaceBlob = "space-blob"
    case plcHistory = "plc-history"
    case identitySnapshot = "identity-snapshot"
}

public struct SwanPortableExportFile: Codable, Sendable, Equatable {
    public let path: String
    public let byteCount: Int
    public let sha256: String
    public let type: SwanPortableExportFileType

    public init(
        path: String,
        byteCount: Int,
        sha256: String,
        type: SwanPortableExportFileType
    ) throws {
        guard byteCount >= 0,
              SwanPortableExportDigest.isCanonicalHex(sha256),
              SwanPortableExportPath.isSafeRelative(path) else {
            throw SwanPortableExportError.invalidManifest
        }
        self.path = path
        self.byteCount = byteCount
        self.sha256 = sha256
        self.type = type
    }
}

public struct SwanPortableExportManifest: Codable, Sendable, Equatable {
    public static let formatValue = "swan-account-export-v2"
    public static let plcHistoryScopeValue = "locally-retained-genesis"
    // The inventory caps allow at most 100,000 permissioned repositories and
    // 100,000 blob references, plus the public CAR and PLC history entries.
    // Keep the manifest itself bounded before JSON decoding can retain an
    // attacker-controlled file list.
    static let maximumFileCount = 200_002

    public let format: String
    public let profileID: String
    public let did: String
    public let canonicalHandle: String
    public let createdAt: String
    public let plcHistoryScope: String
    public let includesPrivateKeys: Bool
    public let files: [SwanPortableExportFile]

    public init(
        profileID: String,
        did: String,
        canonicalHandle: String,
        createdAt: String,
        files: [SwanPortableExportFile]
    ) throws {
        guard profileID == PermissionedData0016.profileID,
              try AccountIdentifiers.validateDID(did) == did,
              try AccountIdentifiers.canonicalHandle(canonicalHandle) == canonicalHandle,
              SwanPortableExportTimestamp.isCanonical(createdAt),
              !files.isEmpty,
              files.count <= Self.maximumFileCount,
              files.map(\.path) == files.map(\.path).sorted(),
              Set(files.map(\.path)).count == files.count else {
            throw SwanPortableExportError.invalidManifest
        }
        format = Self.formatValue
        self.profileID = profileID
        self.did = did
        self.canonicalHandle = canonicalHandle
        self.createdAt = createdAt
        plcHistoryScope = Self.plcHistoryScopeValue
        includesPrivateKeys = false
        self.files = files
    }
}

public enum SwanPortableExportError: Error, Sendable, Equatable {
    case invalidManifest
    case invalidPlacement
    case invalidArchive
    case invalidAccount
    case missingSource
    case publicationFailed
}

public enum SwanPortableExportDigest {
    public static func hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    public static func isCanonicalHex(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy {
            ($0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9"))
                || ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "f"))
        }
    }
}

public enum SwanPortableExportPath {
    public static func encode(_ value: String) -> String {
        Data(value.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func decode(_ value: String) throws -> String {
        guard !value.isEmpty, value.utf8.count <= 8_192,
              value.utf8.allSatisfy({
                  ($0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z"))
                      || ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z"))
                      || ($0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9"))
                      || $0 == UInt8(ascii: "-") || $0 == UInt8(ascii: "_")
              }) else {
            throw SwanPortableExportError.invalidManifest
        }
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64.append(String(repeating: "=", count: (4 - base64.count % 4) % 4))
        guard let data = Data(base64Encoded: base64),
              let decoded = String(data: data, encoding: .utf8),
              encode(decoded) == value else {
            throw SwanPortableExportError.invalidManifest
        }
        return decoded
    }

    public static func isSafeRelative(_ value: String) -> Bool {
        guard !value.isEmpty, !value.hasPrefix("/"), value.utf8.count <= 16_384 else {
            return false
        }
        let components = value.split(separator: "/", omittingEmptySubsequences: false)
        return !components.isEmpty && components.allSatisfy {
            !$0.isEmpty && $0 != "." && $0 != ".."
        }
    }
}

public enum SwanPortableExportManifestCodec {
    private static let rootKeys = Set([
        "format", "profileID", "did", "canonicalHandle", "createdAt",
        "plcHistoryScope", "includesPrivateKeys", "files",
    ])
    private static let fileKeys = Set(["path", "byteCount", "sha256", "type"])

    public static func encode(_ manifest: SwanPortableExportManifest) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(manifest)
    }

    public static func decode(_ data: Data) throws -> SwanPortableExportManifest {
        guard !data.isEmpty, data.count <= 4 * 1_024 * 1_024,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == rootKeys,
              object["format"] as? String == SwanPortableExportManifest.formatValue,
              object["plcHistoryScope"] as? String
                == SwanPortableExportManifest.plcHistoryScopeValue,
              object["includesPrivateKeys"] as? Bool == false,
              let rawFiles = object["files"] as? [[String: Any]],
              rawFiles.allSatisfy({ Set($0.keys) == fileKeys }) else {
            throw SwanPortableExportError.invalidManifest
        }
        let decoded: SwanPortableExportManifest
        do {
            decoded = try JSONDecoder().decode(SwanPortableExportManifest.self, from: data)
        } catch {
            throw SwanPortableExportError.invalidManifest
        }
        let reconstructed = try SwanPortableExportManifest(
            profileID: decoded.profileID,
            did: decoded.did,
            canonicalHandle: decoded.canonicalHandle,
            createdAt: decoded.createdAt,
            files: decoded.files.map {
                try SwanPortableExportFile(
                    path: $0.path,
                    byteCount: $0.byteCount,
                    sha256: $0.sha256,
                    type: $0.type
                )
            }
        )
        guard try encode(reconstructed) == data else {
            throw SwanPortableExportError.invalidManifest
        }
        return reconstructed
    }
}

public enum SwanPortableExportVerifier {
    /// Compatibility-only synchronous verification is deliberately limited;
    /// production callers must use the streaming async API for larger files.
    static let maximumSynchronousArtifactBytes = 8 * 1_024 * 1_024

    public static func verifyArchive(
        at root: URL
    ) throws -> SwanPortableArchiveVerification {
        let descriptor = try SwanPortableExportFilesystem.openArchiveRoot(root)
        defer { _ = close(descriptor) }
        return try verifySelfContainedArchive(directoryDescriptor: descriptor)
    }

    public static func verifyArchive(
        at root: URL,
        signingPublicKey: P256.Signing.PublicKey
    ) throws -> SwanPortableExportManifest {
        let descriptor = try SwanPortableExportFilesystem.openArchiveRoot(root)
        defer { _ = close(descriptor) }
        return try verifyArchive(
            directoryDescriptor: descriptor,
            signingPublicKey: signingPublicKey
        )
    }

    public static func verifyArchiveStreaming(
        at root: URL
    ) async throws -> SwanPortableArchiveVerification {
        let descriptor = try SwanPortableExportFilesystem.openArchiveRoot(root)
        defer { _ = close(descriptor) }
        return try await verifySelfContainedArchiveStreaming(
            directoryDescriptor: descriptor
        )
    }

    public static func verifyArchiveStreaming(
        at root: URL,
        signingPublicKey: P256.Signing.PublicKey
    ) async throws -> SwanPortableExportManifest {
        let descriptor = try SwanPortableExportFilesystem.openArchiveRoot(root)
        defer { _ = close(descriptor) }
        return try await verifyArchiveStreaming(
            directoryDescriptor: descriptor,
            signingPublicKey: signingPublicKey
        )
    }

    static func verifyArchive(
        directoryDescriptor: Int32,
        signingPublicKey: P256.Signing.PublicKey
    ) throws -> SwanPortableExportManifest {
        try SwanPortableExportFilesystem.requireOwnerOnlyDirectory(directoryDescriptor)
        let manifestData = try SwanPortableExportFilesystem.read(
            path: "manifest.json",
            root: directoryDescriptor,
            maximumBytes: 4 * 1_024 * 1_024
        )
        let manifest = try SwanPortableExportManifestCodec.decode(manifestData)
        let expectedPaths = Set(manifest.files.map(\.path) + ["manifest.json"])
        let expectedDirectories = try SwanPortableExportFilesystem.expectedDirectories(
            for: expectedPaths
        )
        let entries = try SwanPortableExportFilesystem.entries(
            root: directoryDescriptor,
            maximumEntries: expectedPaths.count + expectedDirectories.count
        )
        guard entries.files == expectedPaths,
              entries.directories == expectedDirectories
        else {
            throw SwanPortableExportError.invalidArchive
        }

        var verifiedPublicGenesis: PublicRepositoryGenesis?
        var plcHistory: Data?
        var totalBytes = manifestData.count
        for entry in manifest.files {
            try validatePlacement(entry, manifest: manifest)
            let maximumBytes = switch entry.type {
            case .plcHistory:
                64 * 1_024
            case .identitySnapshot:
                64 * 1_024
            default:
                Self.maximumSynchronousArtifactBytes
            }
            guard entry.byteCount <= maximumBytes,
                  totalBytes <= SwanPortableExportFilesystem.maximumArchiveBytes - entry.byteCount
            else {
                throw SwanPortableExportError.invalidArchive
            }
            let data = try SwanPortableExportFilesystem.read(
                path: entry.path,
                root: directoryDescriptor,
                maximumBytes: maximumBytes
            )
            guard data.count == entry.byteCount,
                  SwanPortableExportDigest.hex(data) == entry.sha256 else {
                throw SwanPortableExportError.invalidArchive
            }
            totalBytes += data.count
            switch entry.type {
            case .publicCAR:
                let genesis = try PublicRepositoryGenesisCodec.verify(
                    car: data,
                    publicKey: signingPublicKey
                )
                guard genesis.did == manifest.did else {
                    throw SwanPortableExportError.invalidArchive
                }
                verifiedPublicGenesis = genesis
            case .spaceCAR:
                let components = entry.path.split(separator: "/").map(String.init)
                let space = try SpaceURI(SwanPortableExportPath.decode(components[1]))
                let author = try SwanPortableExportPath.decode(
                    String(components[2].dropLast(4))
                )
                _ = try SpaceCARCodec.verify(
                    data,
                    space: space,
                    author: author,
                    publicKey: signingPublicKey
                )
            case .publicBlob, .spaceBlob:
                let cidComponent = entry.path.split(separator: "/").last.map(String.init)!
                let cid = try SwanPortableExportPath.decode(cidComponent)
                try verifyBlob(data, cid: cid)
            case .plcHistory:
                plcHistory = data
            case .identitySnapshot:
                let snapshot = try SwanIdentitySnapshot.decode(data)
                _ = try snapshot.validatedForRestore(accountDID: manifest.did)
            }
        }
        guard let verifiedPublicGenesis, let plcHistory else {
            throw SwanPortableExportError.invalidArchive
        }
        try verifyPLCHistory(
            plcHistory,
            expectedDID: manifest.did,
            expectedHandle: manifest.canonicalHandle,
            expectedRepositoryRevision: verifiedPublicGenesis.revision,
            expectedPublicGenesisCID: verifiedPublicGenesis.commitCID.string,
            expectedSigningDIDKey: SwanAccounts.P256DIDKey(publicKey: signingPublicKey).value
        )
        return manifest
    }

    /// Verifies an export without materializing permissioned CARs or blobs.
    /// The synchronous verifier above remains the small-file restore/test API;
    /// publication uses this path so a hostile archive can consume at most a
    /// bounded parser chunk plus the bounded SQLite recovery index.
    static func verifyArchiveStreaming(
        directoryDescriptor: Int32,
        signingPublicKey: P256.Signing.PublicKey
    ) async throws -> SwanPortableExportManifest {
        try SwanPortableExportFilesystem.requireOwnerOnlyDirectory(directoryDescriptor)
        let manifestData = try SwanPortableExportFilesystem.read(
            path: "manifest.json",
            root: directoryDescriptor,
            maximumBytes: 4 * 1_024 * 1_024
        )
        let manifest = try SwanPortableExportManifestCodec.decode(manifestData)
        let expectedPaths = Set(manifest.files.map(\.path) + ["manifest.json"])
        let expectedDirectories = try SwanPortableExportFilesystem.expectedDirectories(
            for: expectedPaths
        )
        let entries = try SwanPortableExportFilesystem.entries(
            root: directoryDescriptor,
            maximumEntries: expectedPaths.count + expectedDirectories.count
        )
        guard entries.files == expectedPaths,
              entries.directories == expectedDirectories
        else {
            throw SwanPortableExportError.invalidArchive
        }

        var verifiedPublicGenesis: PublicRepositoryGenesis?
        var plcHistory: Data?
        var totalBytes = manifestData.count
        for entry in manifest.files {
            try Task.checkCancellation()
            try validatePlacement(entry, manifest: manifest)
            let maximumBytes = switch entry.type {
            case .plcHistory:
                64 * 1_024
            case .identitySnapshot:
                64 * 1_024
            case .publicCAR:
                4 * 1_024 * 1_024
            default:
                SwanPortableExportFilesystem.maximumArtifactBytes
            }
            guard entry.byteCount <= maximumBytes,
                  totalBytes <= SwanPortableExportFilesystem.maximumArchiveBytes - entry.byteCount
            else {
                throw SwanPortableExportError.invalidArchive
            }
            totalBytes += entry.byteCount

            switch entry.type {
            case .publicCAR:
                let data = try SwanPortableExportFilesystem.read(
                    path: entry.path,
                    root: directoryDescriptor,
                    maximumBytes: maximumBytes
                )
                guard data.count == entry.byteCount,
                      SwanPortableExportDigest.hex(data) == entry.sha256 else {
                    throw SwanPortableExportError.invalidArchive
                }
                let genesis = try PublicRepositoryGenesisCodec.verify(
                    car: data,
                    publicKey: signingPublicKey
                )
                guard genesis.did == manifest.did else {
                    throw SwanPortableExportError.invalidArchive
                }
                verifiedPublicGenesis = genesis
            case .spaceCAR:
                let components = entry.path.split(separator: "/").map(String.init)
                let space = try SpaceURI(SwanPortableExportPath.decode(components[1]))
                let author = try SwanPortableExportPath.decode(
                    String(components[2].dropLast(4))
                )
                let source = try SwanPortableExportFileByteSource(
                    path: entry.path,
                    root: directoryDescriptor
                )
                let index: SQLiteSpaceCARRecoveryIndex
                do {
                    index = try await SQLiteSpaceCARRecoveryIndex.create()
                } catch {
                    await source.close()
                    throw SwanPortableExportError.invalidArchive
                }
                do {
                    _ = try await SpaceCARCodec.verifyStreamingRecovery(
                        from: source,
                        space: space,
                        author: author,
                        contextSignatureVerifier: { envelope in
                            try SpaceCommitCodec.verifyContextSignature(
                                envelope,
                                publicKey: signingPublicKey
                            )
                        },
                        index: index
                    )
                    let digest = try await source.finish()
                    await index.cleanup()
                    guard digest.byteCount == entry.byteCount,
                          digest.sha256 == entry.sha256 else {
                        throw SwanPortableExportError.invalidArchive
                    }
                } catch {
                    await source.close()
                    await index.cleanup()
                    throw SwanPortableExportError.invalidArchive
                }
            case .publicBlob, .spaceBlob:
                let source = try SwanPortableExportFileByteSource(
                    path: entry.path,
                    root: directoryDescriptor
                )
                do {
                    while try await source.read(
                        maximumBytes: SpaceCARBodySpool.maximumChunkBytes
                    ) != nil {
                        try Task.checkCancellation()
                    }
                    let digest = try await source.finish()
                    let cidComponent = entry.path.split(separator: "/").last.map(String.init)!
                    let cid = try SwanPortableExportPath.decode(cidComponent)
                    guard digest.byteCount == entry.byteCount,
                          digest.sha256 == entry.sha256 else {
                        throw SwanPortableExportError.invalidArchive
                    }
                    try verifyStreamingBlobDigest(cid, sha256: digest.sha256)
                } catch {
                    await source.close()
                    throw SwanPortableExportError.invalidArchive
                }
            case .plcHistory:
                let data = try SwanPortableExportFilesystem.read(
                    path: entry.path,
                    root: directoryDescriptor,
                    maximumBytes: maximumBytes
                )
                guard data.count == entry.byteCount,
                      SwanPortableExportDigest.hex(data) == entry.sha256 else {
                    throw SwanPortableExportError.invalidArchive
                }
                plcHistory = data
            case .identitySnapshot:
                let data = try SwanPortableExportFilesystem.read(
                    path: entry.path,
                    root: directoryDescriptor,
                    maximumBytes: maximumBytes
                )
                guard data.count == entry.byteCount,
                      SwanPortableExportDigest.hex(data) == entry.sha256 else {
                    throw SwanPortableExportError.invalidArchive
                }
                let snapshot = try SwanIdentitySnapshot.decode(data)
                _ = try snapshot.validatedForRestore(accountDID: manifest.did)
            }
        }
        guard let verifiedPublicGenesis, let plcHistory else {
            throw SwanPortableExportError.invalidArchive
        }
        try verifyPLCHistory(
            plcHistory,
            expectedDID: manifest.did,
            expectedHandle: manifest.canonicalHandle,
            expectedRepositoryRevision: verifiedPublicGenesis.revision,
            expectedPublicGenesisCID: verifiedPublicGenesis.commitCID.string,
            expectedSigningDIDKey: SwanAccounts.P256DIDKey(publicKey: signingPublicKey).value
        )
        return manifest
    }

    private static func verifyStreamingBlobDigest(
        _ cid: String,
        sha256: String
    ) throws {
        if cid.hasPrefix("sha256:") {
            guard cid == "sha256:\(sha256)" else {
                throw SwanPortableExportError.invalidArchive
            }
            return
        }
        let parsed: CID
        do {
            parsed = try CID.parse(cid)
        } catch {
            throw SwanPortableExportError.invalidArchive
        }
        guard parsed.string == cid,
              parsed.codec == .raw,
              parsed.multihash.algorithm == Multihash.sha256Code,
              parsed.multihash.length == Multihash.sha256Length,
              SwanCore.Hex.encode(parsed.multihash.digest) == sha256 else {
            throw SwanPortableExportError.invalidArchive
        }
    }

    static func verifySelfContainedArchive(
        directoryDescriptor: Int32
    ) throws -> SwanPortableArchiveVerification {
        try SwanPortableExportFilesystem.requireOwnerOnlyDirectory(directoryDescriptor)
        let manifestData = try SwanPortableExportFilesystem.read(
            path: "manifest.json",
            root: directoryDescriptor,
            maximumBytes: 4 * 1_024 * 1_024
        )
        let manifest = try SwanPortableExportManifestCodec.decode(manifestData)
        guard manifest.includesPrivateKeys == false,
              let historyEntry = manifest.files.first(where: {
                  $0.type == .plcHistory && $0.path == "plc/history.json"
              }),
              manifest.files.filter({ $0.type == .plcHistory }).count == 1,
              historyEntry.byteCount <= 64 * 1_024 else {
            throw SwanPortableExportError.invalidArchive
        }
        let historyData = try SwanPortableExportFilesystem.read(
            path: historyEntry.path,
            root: directoryDescriptor,
            maximumBytes: 64 * 1_024
        )
        guard historyData.count == historyEntry.byteCount,
              SwanPortableExportDigest.hex(historyData) == historyEntry.sha256 else {
            throw SwanPortableExportError.invalidArchive
        }
        let signingPublicKey = try bootstrapSigningPublicKey(
            from: historyData,
            expectedDID: manifest.did
        )
        let verifiedManifest = try verifyArchive(
            directoryDescriptor: directoryDescriptor,
            signingPublicKey: signingPublicKey
        )
        guard verifiedManifest == manifest,
              verifiedManifest.includesPrivateKeys == false else {
            throw SwanPortableExportError.invalidArchive
        }
        return SwanPortableArchiveVerification(
            manifest: verifiedManifest,
            manifestSHA256: "sha256:\(SwanPortableExportDigest.hex(manifestData))",
            signingPublicKey: signingPublicKey
        )
    }

    /// Self-contained verification for restore and publication paths. Only
    /// the bounded manifest, PLC history, and public genesis CAR are retained;
    /// permissioned CARs and blobs are authenticated from descriptor-backed
    /// chunks.
    static func verifySelfContainedArchiveStreaming(
        directoryDescriptor: Int32
    ) async throws -> SwanPortableArchiveVerification {
        try SwanPortableExportFilesystem.requireOwnerOnlyDirectory(directoryDescriptor)
        let manifestData = try SwanPortableExportFilesystem.read(
            path: "manifest.json",
            root: directoryDescriptor,
            maximumBytes: 4 * 1_024 * 1_024
        )
        let manifest = try SwanPortableExportManifestCodec.decode(manifestData)
        guard manifest.includesPrivateKeys == false,
              let historyEntry = manifest.files.first(where: {
                  $0.type == .plcHistory && $0.path == "plc/history.json"
              }),
              manifest.files.filter({ $0.type == .plcHistory }).count == 1,
              historyEntry.byteCount <= 64 * 1_024 else {
            throw SwanPortableExportError.invalidArchive
        }
        let historyData = try SwanPortableExportFilesystem.read(
            path: historyEntry.path,
            root: directoryDescriptor,
            maximumBytes: 64 * 1_024
        )
        guard historyData.count == historyEntry.byteCount,
              SwanPortableExportDigest.hex(historyData) == historyEntry.sha256 else {
            throw SwanPortableExportError.invalidArchive
        }
        let signingPublicKey = try bootstrapSigningPublicKey(
            from: historyData,
            expectedDID: manifest.did
        )
        let verifiedManifest = try await verifyArchiveStreaming(
            directoryDescriptor: directoryDescriptor,
            signingPublicKey: signingPublicKey
        )
        guard verifiedManifest == manifest,
              verifiedManifest.includesPrivateKeys == false else {
            throw SwanPortableExportError.invalidArchive
        }
        return SwanPortableArchiveVerification(
            manifest: verifiedManifest,
            manifestSHA256: "sha256:\(SwanPortableExportDigest.hex(manifestData))",
            signingPublicKey: signingPublicKey
        )
    }

    private static func validatePlacement(
        _ entry: SwanPortableExportFile,
        manifest: SwanPortableExportManifest
    ) throws {
        let parts = entry.path.split(separator: "/", omittingEmptySubsequences: false)
            .map(String.init)
        switch entry.type {
        case .publicCAR:
            guard entry.path == "public/repository.car" else { throw SwanPortableExportError.invalidManifest }
        case .plcHistory:
            guard entry.path == "plc/history.json" else { throw SwanPortableExportError.invalidManifest }
        case .identitySnapshot:
            guard entry.path == "identity/snapshot.json" else { throw SwanPortableExportError.invalidManifest }
        case .spaceCAR:
            guard parts.count == 3, parts[0] == "spaces", parts[2].hasSuffix(".car") else {
                throw SwanPortableExportError.invalidManifest
            }
            let rawSpace = try SwanPortableExportPath.decode(parts[1])
            let rawAuthor = try SwanPortableExportPath.decode(String(parts[2].dropLast(4)))
            guard try SpaceURI(rawSpace).rawValue == rawSpace,
                  try AccountIdentifiers.validateDID(rawAuthor) == rawAuthor,
                  rawAuthor == manifest.did else {
                throw SwanPortableExportError.invalidManifest
            }
        case .publicBlob:
            guard parts.count == 3, parts[0] == "blobs", parts[1] == "public" else {
                throw SwanPortableExportError.invalidManifest
            }
            _ = try SwanPortableExportPath.decode(parts[2])
        case .spaceBlob:
            guard parts.count == 4, parts[0] == "blobs", parts[1] == "space" else {
                throw SwanPortableExportError.invalidManifest
            }
            let rawSpace = try SwanPortableExportPath.decode(parts[2])
            guard try SpaceURI(rawSpace).rawValue == rawSpace else {
                throw SwanPortableExportError.invalidManifest
            }
            _ = try SwanPortableExportPath.decode(parts[3])
        }
    }

    private static func verifyBlob(_ data: Data, cid: String) throws {
        if cid.hasPrefix("sha256:") {
            guard cid == "sha256:\(SwanPortableExportDigest.hex(data))" else {
                throw SwanPortableExportError.invalidArchive
            }
            return
        }
        guard CID.fromBlob(data).string == cid else {
            throw SwanPortableExportError.invalidArchive
        }
    }

    private static func verifyPLCHistory(
        _ data: Data,
        expectedDID: String,
        expectedHandle: String,
        expectedRepositoryRevision: String,
        expectedPublicGenesisCID: String,
        expectedSigningDIDKey: String
    ) throws {
        let expectedKeys = Set([
            "format", "scope", "did", "operationCID", "operation",
            "canonicalHandle", "pdsOrigin", "repositoryRevision",
            "publicGenesisCommitCID", "signingKeyBinding",
        ])
        guard data.count <= 64 * 1_024,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == expectedKeys,
              object["format"] as? String == "swan-plc-history-v1",
              object["scope"] as? String
                == SwanPortableExportManifest.plcHistoryScopeValue,
              object["signingKeyBinding"] as? String
                == SwanPortableExportPLC.signingKeyBindingValue,
              object["did"] as? String == expectedDID,
              let operationObject = object["operation"],
              let operationCID = object["operationCID"] as? String,
              let handle = object["canonicalHandle"] as? String,
              let pdsOrigin = object["pdsOrigin"] as? String,
              let repositoryRevision = object["repositoryRevision"] as? String,
              let publicGenesisCommitCID = object["publicGenesisCommitCID"] as? String,
              handle == expectedHandle,
              repositoryRevision == expectedRepositoryRevision,
              publicGenesisCommitCID == expectedPublicGenesisCID else {
            throw SwanPortableExportError.invalidArchive
        }
        let operationData = try JSONSerialization.data(
            withJSONObject: operationObject,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let operation = try PLCOperationCodec.decodeSignedJSON(operationData)
        try PLCOperationCodec.verifyGenesis(operation, expectedDID: expectedDID)
        guard try operation.cid.string == operationCID,
              operation.regular?.verificationMethods["atproto"] == expectedSigningDIDKey,
              operation.regular?.alsoKnownAs == ["at://\(handle)"],
              operation.regular?.services["atproto_pds"]?.endpoint == pdsOrigin else {
            throw SwanPortableExportError.invalidArchive
        }
    }

    private static func bootstrapSigningPublicKey(
        from data: Data,
        expectedDID: String
    ) throws -> P256.Signing.PublicKey {
        let expectedKeys = Set([
            "format", "scope", "did", "operationCID", "operation",
            "canonicalHandle", "pdsOrigin", "repositoryRevision",
            "publicGenesisCommitCID", "signingKeyBinding",
        ])
        guard data.count <= 64 * 1_024,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == expectedKeys,
              object["format"] as? String == "swan-plc-history-v1",
              object["scope"] as? String
                == SwanPortableExportManifest.plcHistoryScopeValue,
              object["signingKeyBinding"] as? String
                == SwanPortableExportPLC.signingKeyBindingValue,
              object["did"] as? String == expectedDID,
              let operationObject = object["operation"] else {
            throw SwanPortableExportError.invalidArchive
        }
        let canonicalHistory = try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        guard canonicalHistory == data else {
            throw SwanPortableExportError.invalidArchive
        }
        let operationData = try JSONSerialization.data(
            withJSONObject: operationObject,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        let operation = try PLCOperationCodec.decodeSignedJSON(operationData)
        try PLCOperationCodec.verifyGenesis(operation, expectedDID: expectedDID)
        guard let regular = operation.regular,
              let signingDIDKey = regular.verificationMethods["atproto"] else {
            throw SwanPortableExportError.invalidArchive
        }
        let canonicalDIDKey = try SwanAccounts.P256DIDKey(signingDIDKey)
        guard canonicalDIDKey.value == signingDIDKey else {
            throw SwanPortableExportError.invalidArchive
        }
        return try canonicalDIDKey.publicKey
    }

}

public struct SwanPortableArchiveVerification: Sendable {
    public let manifest: SwanPortableExportManifest
    public let manifestSHA256: String
    public let signingPublicKey: P256.Signing.PublicKey

    init(
        manifest: SwanPortableExportManifest,
        manifestSHA256: String,
        signingPublicKey: P256.Signing.PublicKey
    ) {
        self.manifest = manifest
        self.manifestSHA256 = manifestSHA256
        self.signingPublicKey = signingPublicKey
    }
}

public struct SwanPortableExportResult: Codable, Sendable, Equatable {
    public let did: String
    public let outputDirectory: String
    public let manifestSHA256: String
    public let fileCount: Int
    public let includesPrivateKeys: Bool
}

public struct SwanPortableAccountExporter: Sendable {
    private let profileID: String
    private let database: SQLiteAccountDatabase
    private let keyStore: any AccountKeyMaterialReader
    private let now: @Sendable () -> Date
    private let afterArtifactWrite: (@Sendable (Int) throws -> Void)?
    private let afterRenameBeforeParentSync: (@Sendable () throws -> Void)?
    private let identitySnapshotProvider: (@Sendable (String) async throws -> SwanIdentitySnapshot)?

    public init(
        profileID: String = PermissionedData0016.profileID,
        database: SQLiteAccountDatabase,
        keyStore: any AccountKeyMaterialReader,
        now: @escaping @Sendable () -> Date = Date.init,
        identitySnapshotProvider: (@Sendable (String) async throws -> SwanIdentitySnapshot)? = nil
    ) throws {
        guard profileID == PermissionedData0016.profileID else {
            throw SwanPortableExportError.invalidManifest
        }
        self.profileID = profileID
        self.database = database
        self.keyStore = keyStore
        self.now = now
        afterArtifactWrite = nil
        afterRenameBeforeParentSync = nil
        self.identitySnapshotProvider = identitySnapshotProvider
    }

    init(
        profileID: String = PermissionedData0016.profileID,
        database: SQLiteAccountDatabase,
        keyStore: any AccountKeyMaterialReader,
        now: @escaping @Sendable () -> Date = Date.init,
        afterArtifactWrite: @escaping @Sendable (Int) throws -> Void
    ) throws {
        guard profileID == PermissionedData0016.profileID else {
            throw SwanPortableExportError.invalidManifest
        }
        self.profileID = profileID
        self.database = database
        self.keyStore = keyStore
        self.now = now
        self.afterArtifactWrite = afterArtifactWrite
        afterRenameBeforeParentSync = nil
        identitySnapshotProvider = nil
    }

    init(
        profileID: String = PermissionedData0016.profileID,
        database: SQLiteAccountDatabase,
        keyStore: any AccountKeyMaterialReader,
        now: @escaping @Sendable () -> Date = Date.init,
        afterRenameBeforeParentSync: @escaping @Sendable () throws -> Void
    ) throws {
        guard profileID == PermissionedData0016.profileID else {
            throw SwanPortableExportError.invalidManifest
        }
        self.profileID = profileID
        self.database = database
        self.keyStore = keyStore
        self.now = now
        afterArtifactWrite = nil
        self.afterRenameBeforeParentSync = afterRenameBeforeParentSync
        identitySnapshotProvider = nil
    }

    public func export(
        account: AccountControlAccount,
        to outputDirectory: URL
    ) async throws -> SwanPortableExportResult {
        let destination = try SwanPortableExportDestination(outputDirectory)
        return try await export(account: account, to: destination)
    }

    public func export(
        account: AccountControlAccount,
        to destination: SwanPortableExportDestination
    ) async throws -> SwanPortableExportResult {
        guard account.status == .active,
              let signing = account.signingKey,
              let expectedGenesisCID = account.publicGenesisCommitCID else {
            throw SwanPortableExportError.invalidAccount
        }
        let keyReference = try AccountKeyReference(
            accountDID: account.did,
            purpose: .signing,
            generation: signing.generation
        )
        let privateKey = try P256.Signing.PrivateKey(
            rawRepresentation: await keyStore.key(for: keyReference)
        )
        let stagingName = ".swan-export-\(UUID().uuidString.lowercased())"
        let stagingDescriptor = try SwanPortableExportFilesystem.createStagingDirectory(
            parent: destination.parentDescriptor,
            name: stagingName
        )
        var stagingClosed = false
        do {
            var writer = StagedArtifactWriter(
                root: stagingDescriptor,
                afterWrite: afterArtifactWrite
            )

            // Keep the public genesis CAR scoped to this block. The writer
            // records only its digest and size, so an export never retains
            // previously emitted artifacts in an aggregate [Data] array.
            do {
                guard let publicGenesis = try await database.loadPublicRepositoryGenesis(
                    did: account.did,
                    signingPublicKey: privateKey.publicKey
                ), publicGenesis.genesis.commitCID.string == expectedGenesisCID else {
                    throw SwanPortableExportError.missingSource
                }
                try writer.write(
                    path: "public/repository.car",
                    type: SwanPortableExportFileType.publicCAR,
                    data: publicGenesis.genesis.car
                )
            }

            let inventory = try await database.portableExportInventory()
            let journal = try await database.plcAccountPreparationJournal()
            let plcHistory = try makePLCHistory(
                journal: journal,
                did: account.did,
                expectedGenesisCID: expectedGenesisCID,
                signingPublicKey: privateKey.publicKey
            )

            for repository in inventory.repositories {
                try Task.checkCancellation()
                guard let snapshot = try await database.prepareRepositoryCARSnapshot(
                    space: repository.space,
                    author: repository.author
                ), let revision = snapshot.state.wireRevision else {
                    throw SwanPortableExportError.missingSource
                }
                let envelope = try SpaceCommitCodec.createReaderEnvelope(
                    space: repository.space,
                    author: repository.author,
                    rev: revision,
                    commitment: snapshot.state.commitment,
                    key: privateKey
                )
                let prefix = try SpaceCARCodec.recoveryPrefix(
                    commit: envelope,
                    indexCID: snapshot.spool.indexCID
                )
                let spacePath = "spaces/\(SwanPortableExportPath.encode(repository.space.rawValue))/\(SwanPortableExportPath.encode(repository.author)).car"
                _ = try await writer.writeStreaming(
                    path: spacePath,
                    type: SwanPortableExportFileType.spaceCAR
                ) { consume in
                    defer { snapshot.spool.cleanup() }
                    try Task.checkCancellation()
                    try await consume(prefix)
                    try await snapshot.spool.streamBody(consume: consume)
                }
            }

            for reference in inventory.blobs {
                try Task.checkCancellation()
                let type: SwanPortableExportFileType
                let path: String
                switch reference.namespace {
                case .public:
                    type = .publicBlob
                    path = "blobs/public/\(SwanPortableExportPath.encode(reference.cid))"
                case let .space(space):
                    type = .spaceBlob
                    path = "blobs/space/\(SwanPortableExportPath.encode(space.rawValue))/\(SwanPortableExportPath.encode(reference.cid))"
                case .staged:
                    // An uncommitted upload is not account data. The export
                    // inventory already excludes staged edges; reaching here
                    // means the inventory projection has drifted.
                    throw SwanPortableExportError.invalidPlacement
                }
                let written = try await writer.writeStreaming(path: path, type: type) { consume in
                    try await database.streamBlobData(
                        for: reference,
                        maximumBytes: SwanPortableExportFilesystem.maximumArtifactBytes,
                        consume: consume
                    )
                }
                try verifyStreamingBlobDigest(
                    reference.cid,
                    sha256: written.sha256
                )
            }
            try writer.write(
                path: "plc/history.json",
                type: SwanPortableExportFileType.plcHistory,
                data: plcHistory
            )
            if let identitySnapshotProvider {
                let snapshot = try await identitySnapshotProvider(account.did)
                _ = try snapshot.validatedForRestore(accountDID: account.did)
                try writer.write(
                    path: "identity/snapshot.json",
                    type: SwanPortableExportFileType.identitySnapshot,
                    data: try snapshot.encoded()
                )
            }

            let files = writer.files.sorted { $0.path < $1.path }
            let manifest = try SwanPortableExportManifest(
                profileID: profileID,
                did: account.did,
                canonicalHandle: account.canonicalHandle,
                createdAt: SwanPortableExportTimestamp.render(now()),
                files: files
            )
            let manifestData = try SwanPortableExportManifestCodec.encode(manifest)
            try SwanPortableExportFilesystem.write(
                manifestData,
                path: "manifest.json",
                root: stagingDescriptor
            )
            guard fsync(stagingDescriptor) == 0 else {
                throw SwanPortableExportError.publicationFailed
            }
            let stagedVerification = try await SwanPortableExportVerifier
                .verifySelfContainedArchiveStreaming(
                    directoryDescriptor: stagingDescriptor
                )
            try requireSameVerification(
                stagedVerification,
                manifest: manifest,
                manifestData: manifestData,
                signingPublicKey: privateKey.publicKey
            )
            try destination.requireCurrentParentAndAbsentTarget()
            try Task.checkCancellation()
            try SwanPortableExportFilesystem.renameExclusively(
                parent: destination.parentDescriptor,
                source: stagingName,
                destination: destination.outputName
            )
            try afterRenameBeforeParentSync?()
            try destination.requireCurrentParentAndInstalledTarget()
            guard try SwanPortableExportFilesystem.currentChildDirectoryMatches(
                parent: destination.parentDescriptor,
                name: destination.outputName,
                expectedDescriptor: stagingDescriptor
            ) else {
                throw SwanPortableExportError.publicationFailed
            }
            let installedVerification = try await SwanPortableExportVerifier
                .verifySelfContainedArchiveStreaming(
                    directoryDescriptor: stagingDescriptor
                )
            try requireSameVerification(
                installedVerification,
                expected: stagedVerification
            )
            guard try SwanPortableExportFilesystem.currentChildDirectoryMatches(
                parent: destination.parentDescriptor,
                name: destination.outputName,
                expectedDescriptor: stagingDescriptor
            ) else {
                throw SwanPortableExportError.publicationFailed
            }
            try SwanPortableExportFilesystem.synchronizeParent(
                destination.parentDescriptor
            )
            try destination.requireCurrentParentAndInstalledTarget()
            guard try SwanPortableExportFilesystem.currentChildDirectoryMatches(
                parent: destination.parentDescriptor,
                name: destination.outputName,
                expectedDescriptor: stagingDescriptor
            ) else {
                throw SwanPortableExportError.publicationFailed
            }
            _ = close(stagingDescriptor)
            stagingClosed = true
            return SwanPortableExportResult(
                did: account.did,
                outputDirectory: destination.url.path,
                manifestSHA256: "sha256:\(SwanPortableExportDigest.hex(manifestData))",
                fileCount: files.count,
                includesPrivateKeys: false
            )
        } catch {
            do {
                try SwanPortableExportFilesystem.removeTree(
                    parent: destination.parentDescriptor,
                    matching: stagingDescriptor
                )
            } catch {
                if !stagingClosed {
                    _ = close(stagingDescriptor)
                }
                throw SwanPortableExportError.publicationFailed
            }
            if !stagingClosed {
                _ = close(stagingDescriptor)
            }
            throw error
        }
    }

    private func requireSameVerification(
        _ verification: SwanPortableArchiveVerification,
        manifest: SwanPortableExportManifest,
        manifestData: Data,
        signingPublicKey: P256.Signing.PublicKey
    ) throws {
        guard verification.manifest == manifest,
              verification.manifestSHA256
                == "sha256:\(SwanPortableExportDigest.hex(manifestData))",
              verification.signingPublicKey.compressedRepresentation
                == signingPublicKey.compressedRepresentation else {
            throw SwanPortableExportError.publicationFailed
        }
    }

    private func requireSameVerification(
        _ candidate: SwanPortableArchiveVerification,
        expected: SwanPortableArchiveVerification
    ) throws {
        guard candidate.manifest == expected.manifest,
              candidate.manifestSHA256 == expected.manifestSHA256,
              candidate.signingPublicKey.compressedRepresentation
                == expected.signingPublicKey.compressedRepresentation else {
            throw SwanPortableExportError.publicationFailed
        }
    }

    private func makePLCHistory(
        journal: PLCAccountPreparationJournal?,
        did: String,
        expectedGenesisCID: String,
        signingPublicKey: P256.Signing.PublicKey
    ) throws -> Data {
        guard let journal, journal.stage == .submitted,
              journal.publicGenesisCommitCID == expectedGenesisCID else {
            throw SwanPortableExportError.missingSource
        }
        let operation = try PLCOperationCodec.reconstructGenesis(
            signingDIDKey: journal.operation.signingDIDKey,
            rotationDIDKey: journal.operation.rotationDIDKey,
            canonicalHandle: journal.canonicalHandle,
            pdsOrigin: journal.pdsOrigin,
            signature: journal.operation.signature
        )
        try PLCOperationCodec.verifyGenesis(operation, expectedDID: did)
        guard operation.regular?.verificationMethods["atproto"]
            == SwanAccounts.P256DIDKey(publicKey: signingPublicKey).value else {
            throw SwanPortableExportError.invalidAccount
        }
        let object: [String: Any] = [
            "format": "swan-plc-history-v1",
            "scope": SwanPortableExportManifest.plcHistoryScopeValue,
            "did": did,
            "operationCID": try operation.cid.string,
            "operation": try JSONSerialization.jsonObject(with: operation.canonicalJSON),
            "canonicalHandle": journal.canonicalHandle,
            "pdsOrigin": journal.pdsOrigin,
            "repositoryRevision": journal.repositoryRevision,
            "publicGenesisCommitCID": expectedGenesisCID,
            // V1 intentionally binds an export to the current PLC `atproto`
            // verification method. A future signing-key rotation profile must
            // introduce a new value and verification rule rather than silently
            // weakening this alpha invariant.
            "signingKeyBinding": SwanPortableExportPLC.signingKeyBindingValue,
        ]
        return try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
    }

    private func verifyStreamingBlobDigest(
        _ cid: String,
        sha256: String
    ) throws {
        if cid.hasPrefix("sha256:") {
            guard cid == "sha256:\(sha256)" else {
                throw SwanPortableExportError.invalidArchive
            }
            return
        }
        let parsed: CID
        do {
            parsed = try CID.parse(cid)
        } catch {
            throw SwanPortableExportError.invalidArchive
        }
        guard parsed.string == cid,
              parsed.codec == .raw,
              parsed.multihash.algorithm == Multihash.sha256Code,
              parsed.multihash.length == Multihash.sha256Length,
              SwanCore.Hex.encode(parsed.multihash.digest) == sha256 else {
            throw SwanPortableExportError.invalidArchive
        }
    }

    private final class StreamingArtifactAccumulator: @unchecked Sendable {
        private let writer: SwanPortableExportFilesystem.StreamingWriter
        private let maximumBytes: Int
        private let lock = NSLock()
        private var hasher = SHA256()
        private var count = 0
        private var finished = false

        init(
            writer: SwanPortableExportFilesystem.StreamingWriter,
            maximumBytes: Int
        ) {
            self.writer = writer
            self.maximumBytes = maximumBytes
        }

        func append(_ data: Data) throws {
            lock.lock()
            defer { lock.unlock() }
            guard !finished, !data.isEmpty else {
                if data.isEmpty { return }
                throw SwanPortableExportError.publicationFailed
            }
            let (next, overflow) = count.addingReportingOverflow(data.count)
            guard !overflow, next <= maximumBytes else {
                throw SwanPortableExportError.invalidArchive
            }
            hasher.update(data: data)
            try writer.write(data)
            count = next
        }

        func finish() throws -> (byteCount: Int, sha256: String) {
            lock.lock()
            defer { lock.unlock() }
            guard !finished else {
                throw SwanPortableExportError.publicationFailed
            }
            try writer.finish()
            finished = true
            return (count, SwanCore.Hex.encode(Data(hasher.finalize())))
        }

        func abort() {
            lock.lock()
            guard !finished else {
                lock.unlock()
                return
            }
            finished = true
            lock.unlock()
            writer.abort()
        }
    }

    private struct StagedArtifactWriter {
        private static let manifestReserveBytes = 4 * 1_024 * 1_024
        let root: Int32
        let afterWrite: (@Sendable (Int) throws -> Void)?
        private(set) var files: [SwanPortableExportFile] = []
        private var paths = Set<String>()
        private var artifactBytes = 0

        init(
            root: Int32,
            afterWrite: (@Sendable (Int) throws -> Void)?
        ) {
            self.root = root
            self.afterWrite = afterWrite
        }

        mutating func write(
            path: String,
            type: SwanPortableExportFileType,
            data: Data
        ) throws {
            guard paths.insert(path).inserted else {
                throw SwanPortableExportError.invalidArchive
            }
            guard data.count <= SwanPortableExportFilesystem.maximumArtifactBytes,
                  artifactBytes <= SwanPortableExportFilesystem.maximumArchiveBytes
                    - Self.manifestReserveBytes - data.count else {
                throw SwanPortableExportError.invalidArchive
            }
            try SwanPortableExportFilesystem.write(data, path: path, root: root)
            artifactBytes += data.count
            files.append(
                try SwanPortableExportFile(
                    path: path,
                    byteCount: data.count,
                    sha256: SwanPortableExportDigest.hex(data),
                    type: type
                )
            )
            try afterWrite?(files.count)
        }

        mutating func writeStreaming(
            path: String,
            type: SwanPortableExportFileType,
            source: @escaping @Sendable (
                @escaping @Sendable (Data) async throws -> Void
            ) async throws -> Void
        ) async throws -> (byteCount: Int, sha256: String) {
            guard paths.insert(path).inserted else {
                throw SwanPortableExportError.invalidArchive
            }
            let remaining = SwanPortableExportFilesystem.maximumArchiveBytes
                - Self.manifestReserveBytes - artifactBytes
            guard remaining > 0 else {
                throw SwanPortableExportError.invalidArchive
            }
            let writer = try SwanPortableExportFilesystem.openStreamingWriter(
                path: path,
                root: root
            )
            let accumulator = StreamingArtifactAccumulator(
                writer: writer,
                maximumBytes: min(
                    SwanPortableExportFilesystem.maximumArtifactBytes,
                    remaining
                )
            )
            do {
                try await source { chunk in
                    try accumulator.append(chunk)
                }
                let result = try accumulator.finish()
                artifactBytes += result.byteCount
                files.append(
                    try SwanPortableExportFile(
                        path: path,
                        byteCount: result.byteCount,
                        sha256: result.sha256,
                        type: type
                    )
                )
                try afterWrite?(files.count)
                return result
            } catch {
                accumulator.abort()
                throw error
            }
        }
    }
}

private enum SwanPortableExportPLC {
    static let signingKeyBindingValue = "plc-atproto-current-v1"
}

enum SwanPortableExportTimestamp {
    static func render(_ date: Date) -> String {
        formatter().string(from: date)
    }

    static func isCanonical(_ value: String) -> Bool {
        guard value.utf8.count == 24,
              let date = formatter().date(from: value) else {
            return false
        }
        return render(date) == value
    }

    private static func formatter() -> ISO8601DateFormatter {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [
            .withInternetDateTime, .withFractionalSeconds,
            .withDashSeparatorInDate, .withColonSeparatorInTime,
        ]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter
    }
}

/// Descriptor-backed byte source used only by the bounded archive verifier.
/// It snapshots the file identity/length before parsing, hashes the exact bytes
/// consumed by the parser, and rejects a file that changes underneath it.
actor SwanPortableExportFileByteSource:
    SpaceCARRecoveryByteSource,
    PublicRepositoryCARByteSource
{
    private let descriptor: Int32
    private let device: dev_t
    private let inode: ino_t
    private let byteCount: Int
    private var offset = 0
    private var digest = SHA256()
    private var closed = false

    init(path: String, root: Int32) throws {
        let descriptor = try SwanPortableExportFilesystem.openStreamingReader(
            path: path,
            root: root
        )
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_size >= 0,
              metadata.st_size <= off_t(Int.max) else {
            #if canImport(Darwin)
            _ = Darwin.close(descriptor)
            #elseif canImport(Glibc)
            _ = Glibc.close(descriptor)
            #endif
            throw SwanPortableExportError.invalidArchive
        }
        self.descriptor = descriptor
        device = metadata.st_dev
        inode = metadata.st_ino
        byteCount = Int(metadata.st_size)
    }

    func read(maximumBytes: Int) async throws -> Data? {
        try Task.checkCancellation()
        guard !closed,
              (1 ... SpaceCARBodySpool.maximumChunkBytes).contains(maximumBytes)
        else {
            throw SwanPortableExportError.invalidArchive
        }
        guard offset < byteCount else { return nil }
        let count = min(maximumBytes, byteCount - offset)
        var chunk = Data(count: count)
        let readCount = try chunk.withUnsafeMutableBytes { bytes -> Int in
            while true {
                #if canImport(Darwin)
                let result = Darwin.read(descriptor, bytes.baseAddress!, count)
                #elseif canImport(Glibc)
                let result = Glibc.read(descriptor, bytes.baseAddress!, count)
                #endif
                if result < 0, errno == EINTR { continue }
                guard result > 0, result <= count else {
                    throw SwanPortableExportError.invalidArchive
                }
                return result
            }
        }
        chunk.count = readCount
        offset += readCount
        digest.update(data: chunk)
        return chunk
    }

    func finish() throws -> (byteCount: Int, sha256: String) {
        guard !closed, offset == byteCount else {
            throw SwanPortableExportError.invalidArchive
        }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_dev == device,
              metadata.st_ino == inode,
              metadata.st_size == off_t(byteCount),
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              (metadata.st_mode & 0o777) == 0o600 else {
            close()
            throw SwanPortableExportError.invalidArchive
        }
        let result = (
            byteCount,
            SwanCore.Hex.encode(Data(digest.finalize()))
        )
        close()
        return result
    }

    func close() {
        guard !closed else { return }
        closed = true
        #if canImport(Darwin)
        _ = Darwin.close(descriptor)
        #elseif canImport(Glibc)
        _ = Glibc.close(descriptor)
        #endif
    }
}
