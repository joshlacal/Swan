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
import SwanPublicRepository
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
        let entries = try SwanPortableExportFilesystem.entries(root: directoryDescriptor)
        guard entries.files == expectedPaths,
              entries.directories
                == (try SwanPortableExportFilesystem.expectedDirectories(for: expectedPaths))
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
            default:
                SwanPortableExportFilesystem.maximumArtifactBytes
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
            expectedSigningDIDKey: P256DIDKey(publicKey: signingPublicKey).value
        )
        return manifest
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
        let canonicalDIDKey = try P256DIDKey(signingDIDKey)
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

    public init(
        profileID: String = PermissionedData0016.profileID,
        database: SQLiteAccountDatabase,
        keyStore: any AccountKeyMaterialReader,
        now: @escaping @Sendable () -> Date = Date.init
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
        guard let publicGenesis = try await database.loadPublicRepositoryGenesis(
            did: account.did,
            signingPublicKey: privateKey.publicKey
        ), publicGenesis.genesis.commitCID.string == expectedGenesisCID else {
            throw SwanPortableExportError.missingSource
        }
        let inventory = try await database.portableExportInventory()
        let journal = try await database.plcAccountPreparationJournal()
        let plcHistory = try makePLCHistory(
            journal: journal,
            did: account.did,
            expectedGenesisCID: expectedGenesisCID,
            signingPublicKey: privateKey.publicKey
        )

        var artifacts = [Artifact(
            path: "public/repository.car",
            type: .publicCAR,
            data: publicGenesis.genesis.car
        )]
        for repository in inventory.repositories {
            guard let snapshot = try await database.repositorySnapshot(
                space: repository.space,
                author: repository.author
            ) else {
                throw SwanPortableExportError.missingSource
            }
            let records = try verifiedRecords(snapshot)
            let envelope = try SpaceCommitCodec.createReaderEnvelope(
                space: repository.space,
                author: repository.author,
                rev: snapshot.state.wireRevision.toString(),
                commitment: snapshot.state.commitment,
                key: privateKey
            )
            guard try SpaceCommitCodec.verifyContextSignature(
                envelope,
                publicKey: privateKey.publicKey
            ), SpaceCommitCodec.verifyContentBinding(envelope) else {
                throw SwanPortableExportError.invalidArchive
            }
            let car = try SpaceCARCodec.encode(commit: envelope, records: records)
            _ = try SpaceCARCodec.verify(
                car.data,
                space: repository.space,
                author: repository.author,
                publicKey: privateKey.publicKey
            )
            artifacts.append(.init(
                path: "spaces/\(SwanPortableExportPath.encode(repository.space.rawValue))/\(SwanPortableExportPath.encode(repository.author)).car",
                type: .spaceCAR,
                data: car.data
            ))
        }
        for reference in inventory.blobs {
            let data = try await database.data(for: reference)
            let type: SwanPortableExportFileType
            let path: String
            switch reference.namespace {
            case .public:
                type = .publicBlob
                path = "blobs/public/\(SwanPortableExportPath.encode(reference.cid))"
            case let .space(space):
                type = .spaceBlob
                path = "blobs/space/\(SwanPortableExportPath.encode(space.rawValue))/\(SwanPortableExportPath.encode(reference.cid))"
            }
            artifacts.append(.init(path: path, type: type, data: data))
        }
        artifacts.append(.init(path: "plc/history.json", type: .plcHistory, data: plcHistory))
        artifacts.sort { $0.path < $1.path }
        guard Set(artifacts.map(\.path)).count == artifacts.count else {
            throw SwanPortableExportError.invalidArchive
        }

        let manifest = try SwanPortableExportManifest(
            profileID: profileID,
            did: account.did,
            canonicalHandle: account.canonicalHandle,
            createdAt: SwanPortableExportTimestamp.render(now()),
            files: try artifacts.map {
                try SwanPortableExportFile(
                    path: $0.path,
                    byteCount: $0.data.count,
                    sha256: SwanPortableExportDigest.hex($0.data),
                    type: $0.type
                )
            }
        )
        let manifestData = try SwanPortableExportManifestCodec.encode(manifest)
        try publish(
            artifacts: artifacts,
            manifest: manifestData,
            destination: destination,
            signingPublicKey: privateKey.publicKey
        )
        return SwanPortableExportResult(
            did: account.did,
            outputDirectory: destination.url.path,
            manifestSHA256: "sha256:\(SwanPortableExportDigest.hex(manifestData))",
            fileCount: artifacts.count,
            includesPrivateKeys: false
        )
    }

    private func verifiedRecords(
        _ snapshot: PersistedRepositorySnapshot
    ) throws -> [SpaceRecord] {
        var recomputed = LtHash()
        let records = try snapshot.records.map { record -> SpaceRecord in
            guard CID.fromDAGCBOR(record.value).string == record.cid else {
                throw SwanPortableExportError.invalidArchive
            }
            recomputed.add(
                element: "\(record.uri.collection)/\(record.uri.rkey)/\(record.cid)"
            )
            return .init(
                uri: record.uri,
                value: record.value,
                cid: record.cid,
                revision: record.revision
            )
        }
        guard recomputed.serialized == snapshot.state.ltHash,
              recomputed.commitment == snapshot.state.commitment else {
            throw SwanPortableExportError.invalidArchive
        }
        return records
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
            == P256DIDKey(publicKey: signingPublicKey).value else {
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

    private func publish(
        artifacts: [Artifact],
        manifest: Data,
        destination: SwanPortableExportDestination,
        signingPublicKey: P256.Signing.PublicKey
    ) throws {
        let stagingName = ".swan-export-\(UUID().uuidString.lowercased())"
        let stagingDescriptor = try SwanPortableExportFilesystem.createStagingDirectory(
            parent: destination.parentDescriptor,
            name: stagingName
        )
        var published = false
        do {
            for (index, artifact) in artifacts.enumerated() {
                try SwanPortableExportFilesystem.write(
                    artifact.data,
                    path: artifact.path,
                    root: stagingDescriptor
                )
                try afterArtifactWrite?(index + 1)
            }
            try SwanPortableExportFilesystem.write(
                manifest,
                path: "manifest.json",
                root: stagingDescriptor
            )
            guard fsync(stagingDescriptor) == 0 else {
                throw SwanPortableExportError.publicationFailed
            }
            _ = try SwanPortableExportVerifier.verifyArchive(
                directoryDescriptor: stagingDescriptor,
                signingPublicKey: signingPublicKey
            )
            try destination.requireCurrentParentAndAbsentTarget()
            try SwanPortableExportFilesystem.renameExclusively(
                parent: destination.parentDescriptor,
                source: stagingName,
                destination: destination.outputName
            )
            // `rename` is the publication linearization point. Record the
            // installed state before any later operation can fail so cleanup
            // never targets the now-missing staging name.
            published = true
            try afterRenameBeforeParentSync?()
            try SwanPortableExportFilesystem.synchronizeParent(
                destination.parentDescriptor
            )
            try destination.requireCurrentParentAndInstalledTarget()
            _ = close(stagingDescriptor)
        } catch {
            _ = close(stagingDescriptor)
            SwanPortableExportFilesystem.removeTree(
                parent: destination.parentDescriptor,
                name: published ? destination.outputName : stagingName
            )
            throw error
        }
    }

    private struct Artifact: Sendable {
        let path: String
        let type: SwanPortableExportFileType
        let data: Data
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
