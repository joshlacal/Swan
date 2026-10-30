import Crypto
import Foundation
import PetrelCrypto
import SwanCore
import SwanSpaces
/// A stable, offline-only diagnostic for a checked-in protocol artifact.
///
/// Deliberately do not carry filesystem paths, file contents, or underlying
/// decoding errors here. `swan verify` is safe to use in CI logs, including
/// when the profile directory is mounted from a secret-bearing environment.
public struct ProtocolProfileVerificationDiagnostic: Error, Sendable, Equatable, CustomStringConvertible {
    public enum Code: String, Sendable, Equatable, Codable {
        case unreadableProfile
        case malformedProfile
        case unsupportedProfileID
        case invalidRevisionPin
        case invalidChecksumPin
        case immutableProfilePinMismatch
        case missingArtifactPin
        case invalidArtifactName
        case unreadableLexiconManifest
        case lexiconManifestDigestMismatch
        case malformedLexiconManifest
        case unreadableGeneratedWireManifest
        case generatedWireManifestDigestMismatch
        case malformedGeneratedWireManifest
        case generatedWireSourceMissing
        case generatedWireSourceOutsideRoot
        case generatedWireSourceSymlink
        case generatedWireSourceChecksumMismatch
        case generatedWireSourceSetMismatch
    }

    public let code: Code
    public let artifact: String

    public init(_ code: Code, artifact: String) {
        self.code = code
        self.artifact = artifact
    }

    public var description: String {
        "profile verification failed: \(code.rawValue) (\(artifact))"
    }
}

/// The result of checking a protocol profile without contacting any remote
/// service. A caller can render the stable diagnostics in logs or map them to
/// its own error transport without exposing potentially sensitive local paths.
public struct ProtocolProfileVerificationReport: Sendable, Equatable {
    public let profileID: String?
    public let diagnostics: [ProtocolProfileVerificationDiagnostic]

    public init(profileID: String?, diagnostics: [ProtocolProfileVerificationDiagnostic]) {
        self.profileID = profileID
        self.diagnostics = diagnostics
    }

    public var isValid: Bool { diagnostics.isEmpty }
}

/// Validates the immutable local profile and the checksums for its checked-in
/// artifacts. This verifier is deliberately unable to fetch, unpack, or trust
/// an upstream checkout: profile drift must be visible before network-backed
/// regeneration happens in CI.
public enum OfflineProtocolProfileVerifier {
    // Historical profile baselines: permissioned-data-0016-2026-07-03,
    // permissioned-data-0016-2026-07-30, permissioned-data-0016-2026-08-15,
    // permissioned-data-0016-2026-09-10, permissioned-data-0016-2026-09-19.
    public static let stableProfileID = "permissioned-data-0016-2026-10-22"
    public static let publicProfileID = "public-data-testing-2026-08-06"

    private struct ProfileIdentity: Decodable {
        let id: String
    }

    private struct ArtifactPins: Decodable {
        let id: String
        let proposalCommit: String
        let referenceImplementationCommit: String
        let petrelGeneratorCommit: String
        let petrelCommit: String
        let migrationCompatibility: String
        let crypto: CryptoSuite
        let permissionedDataIsEncrypted: Bool
        let oplogRetention: Int
        let referenceArchiveSHA256: String?
        let petrelManifest: String?
        let petrelManifestSHA256: String?
        let lexiconManifest: String?
        let lexiconManifestSHA256: String?
        let generatedWireManifest: String?
        let generatedWireManifestSHA256: String?
        let endpoints: [String]
    }

    private struct CryptoSuite: Decodable, Equatable {
        let lthashBytes: Int
        let lthashHash: String
        let commitmentHash: String
        let contentBinding: String
    }

    private struct PublicArtifactPins: Decodable {
        struct Divergence: Decodable {
            let endpoint: String
            let referenceBehavior: String
            let swanBehavior: String
        }

        let id: String
        let referenceImplementationCommit: String
        let petrelGeneratorCommit: String
        let petrelCommit: String
        let referenceArchiveSHA256: String?
        let petrelManifest: String?
        let petrelManifestSHA256: String?
        let lexiconManifest: String?
        let lexiconManifestSHA256: String?
        let generatedWireManifest: String?
        let generatedWireManifestSHA256: String?
        let inventorySemantics: String
        let intentionalDivergences: [Divergence]
        let lexicons: [String]
        let endpoints: [String]
    }

    private struct ManifestEntry: Equatable {
        let checksum: String
        let path: String
    }

    // This verifier deliberately supports exactly one immutable profile. Shape
    // validation alone would let a modified JSON file substitute a different
    // well-formed commit or manifest digest and still report success.
    private static let expectedProposalCommit = "b89d0b04495a62e0e22f1ab04c665a9c4e1c655d"
    private static let expectedReferenceImplementationCommit = "ac0c9f15392f6f0298d71dc52aa88c05036150be"
    private static let expectedPetrelGeneratorCommit = "e115236537041a900ec971be05185a70cca73e8a"
    private static let expectedPetrelCommit = "4037e7760e2d1bb71db9a6cfdd0cd4134d4dd3bc"
    private static let expectedReferenceArchiveSHA256 = "eae029a70a3adf0f7d6241814d5a91d55bf6768e8f4cd00196870c911df57eb5"
    private static let expectedProfileSHA256 = "7fa8f20d84051e296e43fc39acd0ad34ecb4656a4bbf648c08182587e3452d60"
    private static let expectedPetrelManifestSHA256 = "59cbe0fde6241a32cc819ebd833edc6fe428a37cde7821a1adf1cc857dd139f9"
    private static let expectedLexiconManifestSHA256 = "fbbf6e9b89507d24d8bffd3df78cd9c5a8d4aa8190f5bf8870bb53281d972bc3"
    private static let expectedGeneratedWireManifestSHA256 = "1bd8bd00ee6c7beb620d0b72e4c6e25d99e1c0563f9958724512ec002606be9a"
    private static let expectedPublicProfileSHA256 = "b96ac7c7fa3df3a0bb5b396c25f776734493d7b0a09a71e1e082e24813b64124"
    // The public profile's own pins: its wire was generated by the pre-SpaceRef
    // generator against the 3f6c96d5 reference and is deliberately not part of
    // the permissioned re-pin.
    private static let expectedPublicReferenceImplementationCommit = "3f6c96d5d2d25438bd40fa89d6ecc37865f8e354"
    private static let expectedPublicPetrelGeneratorCommit = "c2a1cdbee8c621c7682416114700f032cc7e2b37"
    private static let expectedPublicPetrelCommit = "db84b2c9788aa38000ee3f134e21feffa8f351cd"
    private static let expectedPublicReferenceArchiveSHA256 = "1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea"
    private static let expectedPublicPetrelManifestSHA256 = "cb39d0c4264d02540b67adbe668a1224753b507e35e11f19ba97879931804068"
    private static let expectedPublicLexiconManifestSHA256 = "2f14fbc29b2c3414baca5e659fb8dbe85f6b5a5252e13ff677b5b19d4309374d"
    private static let expectedPublicGeneratedWireManifestSHA256 = "80a03ee8bcaed70008b74556add80108f5cf64d96932b21df60e2d18e247dcc7"
    private static let expectedPublicInventorySemantics =
        "lexicons is the exact ordered 21-file source set, including the repo and sync defs files; endpoints is the exact ordered 19-method XRPC contract set and excludes defs."
    private static let expectedEndpoints = [
        "com.atproto.space.applyWrites",
        "com.atproto.space.createRecord",
        "com.atproto.space.deleteRecord",
        "com.atproto.space.getBlob",
        "com.atproto.space.getDelegationToken",
        "com.atproto.space.getLatestCommit",
        "com.atproto.space.getRecord",
        "com.atproto.space.getRepo",
        "com.atproto.space.getSpaceCredential",
        "com.atproto.space.listBlobs",
        "com.atproto.space.listRecords",
        "com.atproto.space.listRepoOps",
        "com.atproto.space.listRepos",
        "com.atproto.space.listSpaces",
        "com.atproto.space.notifyCredentialRevoked",
        "com.atproto.space.notifySpaceDeleted",
        "com.atproto.space.notifyWrite",
        "com.atproto.space.putRecord",
        "com.atproto.space.registerNotify",
        "com.atproto.space.unregisterNotify",
        "com.atproto.simplespace.putMember",
        "com.atproto.simplespace.checkUserAccess",
        "com.atproto.simplespace.createSpace",
        "com.atproto.simplespace.deleteSpace",
        "com.atproto.simplespace.getSpace",
        "com.atproto.simplespace.listMembers",
        "com.atproto.simplespace.removeMember",
        "com.atproto.simplespace.updateSpace",
    ]
    private static let expectedPublicLexicons = [
        "com.atproto.repo.applyWrites",
        "com.atproto.repo.createRecord",
        "com.atproto.repo.defs",
        "com.atproto.repo.deleteRecord",
        "com.atproto.repo.describeRepo",
        "com.atproto.repo.getRecord",
        "com.atproto.repo.listRecords",
        "com.atproto.repo.putRecord",
        "com.atproto.repo.uploadBlob",
        "com.atproto.server.confirmEmail",
        "com.atproto.server.requestEmailConfirmation",
        "com.atproto.server.requestEmailUpdate",
        "com.atproto.server.requestPasswordReset",
        "com.atproto.server.resetPassword",
        "com.atproto.server.updateEmail",
        "com.atproto.sync.defs",
        "com.atproto.sync.getBlob",
        "com.atproto.sync.getLatestCommit",
        "com.atproto.sync.getRepo",
        "com.atproto.sync.getRepoStatus",
        "com.atproto.sync.subscribeRepos",
    ]
    private static let expectedPublicEndpoints = expectedPublicLexicons.filter {
        !$0.hasSuffix(".defs")
    }

    public static func verify(
        profileURL: URL,
        sourceRoot: URL? = nil
    ) -> ProtocolProfileVerificationReport {
        let profileData: Data
        guard !isSymbolicLink(profileURL) else {
            return .init(profileID: nil, diagnostics: [.init(.unreadableProfile, artifact: "profile")])
        }
        do {
            profileData = try Data(contentsOf: profileURL, options: [.mappedIfSafe])
        } catch {
            return .init(profileID: nil, diagnostics: [.init(.unreadableProfile, artifact: "profile")])
        }

        let identity: ProfileIdentity
        do {
            identity = try JSONDecoder().decode(ProfileIdentity.self, from: profileData)
        } catch {
            return .init(profileID: nil, diagnostics: [.init(.malformedProfile, artifact: "profile")])
        }
        switch identity.id {
        case stableProfileID:
            return verifyPermissioned(profileData, profileURL: profileURL, sourceRoot: sourceRoot)
        case publicProfileID:
            return verifyPublic(profileData, profileURL: profileURL, sourceRoot: sourceRoot)
        default:
            return .init(
                profileID: identity.id,
                diagnostics: [.init(.unsupportedProfileID, artifact: "profile")]
            )
        }
    }

    /// Verifies the selected source bytes for the public profile without
    /// widening `ProtocolProfile`, which intentionally models proposal 0016.
    public static func verifyPinnedPublicLexicons(
        profileURL: URL,
        referenceRoot: URL
    ) throws {
        let data = try Data(contentsOf: profileURL)
        let pins = try JSONDecoder().decode(PublicArtifactPins.self, from: data)
        guard Hex.encode(SHA256.hash(data: data)) == expectedPublicProfileSHA256,
              hasExpectedPublicPins(pins),
              let manifestName = pins.lexiconManifest,
              let manifestChecksum = pins.lexiconManifestSHA256 else {
            throw ProtocolProfileVerificationDiagnostic(.immutableProfilePinMismatch, artifact: "profile")
        }
        let manifestURL = profileURL.deletingLastPathComponent().appending(path: manifestName)
        guard !isSymbolicLink(manifestURL) else {
            throw ProtocolProfileVerificationDiagnostic(.unreadableLexiconManifest, artifact: "lexicon manifest")
        }
        let manifestData = try Data(contentsOf: manifestURL)
        guard Hex.encode(SHA256.hash(data: manifestData)) == manifestChecksum,
              let text = String(data: manifestData, encoding: .utf8),
              let entries = parseManifest(
                  text,
                  kind: .lexicon,
                  expectedSourcePrefix: "com/atproto/"
              ),
              entries.count == 21,
              entries.map(\.path) == expectedPublicLexicons.map({
                  $0.replacingOccurrences(of: ".", with: "/") + ".json"
              }) else {
            throw ProtocolProfileVerificationDiagnostic(.malformedLexiconManifest, artifact: "lexicon manifest")
        }
        for entry in entries {
            let source = referenceRoot.appending(path: "lexicons/\(entry.path)")
            guard !isSymbolicLink(source),
                  let bytes = try? Data(contentsOf: source),
                  Hex.encode(SHA256.hash(data: bytes)) == entry.checksum else {
                throw ProtocolProfileVerificationDiagnostic(.malformedLexiconManifest, artifact: "lexicon source")
            }
        }
    }

    private static func verifyPermissioned(
        _ profileData: Data,
        profileURL: URL,
        sourceRoot: URL?
    ) -> ProtocolProfileVerificationReport {
        var diagnostics: [ProtocolProfileVerificationDiagnostic] = []
        let pins: ArtifactPins
        do {
            pins = try JSONDecoder().decode(ArtifactPins.self, from: profileData)
        } catch {
            return .init(profileID: stableProfileID, diagnostics: [.init(.malformedProfile, artifact: "profile")])
        }
        let expectedKeys: Set<String> = [
            "id", "proposalCommit", "referenceImplementationCommit", "petrelGeneratorCommit",
            "petrelCommit", "migrationCompatibility", "crypto",
            "permissionedDataIsEncrypted", "oplogRetention", "referenceArchiveSHA256",
            "petrelManifest", "petrelManifestSHA256",
            "lexiconManifest", "lexiconManifestSHA256", "generatedWireManifest",
            "generatedWireManifestSHA256", "intentionalDivergences",
            "compatibilityExceptions", "retiredCompatibilityExceptions", "endpoints",
        ]
        let actualKeys = ((try? JSONSerialization.jsonObject(with: profileData)) as? [String: Any])
            .map { Set($0.keys) }
        if actualKeys != expectedKeys {
            diagnostics.append(.init(.malformedProfile, artifact: "profile"))
        }
        for revision in [
            pins.proposalCommit,
            pins.referenceImplementationCommit,
            pins.petrelGeneratorCommit,
            pins.petrelCommit,
        ] where !isLowercaseHex(revision, count: 40) {
            diagnostics.append(.init(.invalidRevisionPin, artifact: "profile"))
            break
        }
        if let archiveChecksum = pins.referenceArchiveSHA256 {
            if !isLowercaseHex(archiveChecksum, count: 64) {
                diagnostics.append(.init(.invalidChecksumPin, artifact: "reference archive"))
            }
        } else {
            diagnostics.append(.init(.missingArtifactPin, artifact: "reference archive"))
        }
        if pins.endpoints.isEmpty || Set(pins.endpoints).count != pins.endpoints.count {
            diagnostics.append(.init(.malformedProfile, artifact: "profile"))
        }
        let profileBytesMatch =
            Hex.encode(SHA256.hash(data: profileData)) == expectedProfileSHA256
        if !profileBytesMatch || !hasExpectedImmutablePins(pins) {
            diagnostics.append(.init(.immutableProfilePinMismatch, artifact: "profile"))
        }
        do {
            _ = try ProtocolProfile(data: profileData)
        } catch {
            diagnostics.append(.init(.malformedProfile, artifact: "profile"))
        }

        let permissionedSourceRoot = sourceRoot ??
            profileURL.deletingLastPathComponent().deletingLastPathComponent()
        if let name = pins.petrelManifest,
           let checksum = pins.petrelManifestSHA256,
           name == "PetrelManifest.json",
           isLowercaseHex(checksum, count: 64) {
            let manifestURL = permissionedSourceRoot.appending(path: name)
            if isSymbolicLink(manifestURL) ||
                (try? Data(contentsOf: manifestURL, options: [.mappedIfSafe]))
                    .map({ Hex.encode(SHA256.hash(data: $0)) }) != checksum {
                diagnostics.append(.init(.immutableProfilePinMismatch, artifact: "Petrel manifest"))
            }
        } else {
            diagnostics.append(.init(.immutableProfilePinMismatch, artifact: "Petrel manifest"))
        }

        let expectedLexiconManifest = "\(stableProfileID).lexicons.sha256"
        verifyManifest(
            name: pins.lexiconManifest,
            checksum: pins.lexiconManifestSHA256,
            expectedName: expectedLexiconManifest,
            profileDirectory: profileURL.deletingLastPathComponent(),
            sourceRoot: nil,
            kind: .lexicon,
            expectedSourcePrefix: "com/atproto/",
            generatedTargetRoot: nil,
            diagnostics: &diagnostics
        )

        let expectedWireManifest = "\(stableProfileID).generated-wire.sha256"
        verifyManifest(
            name: pins.generatedWireManifest,
            checksum: pins.generatedWireManifestSHA256,
            expectedName: expectedWireManifest,
            profileDirectory: profileURL.deletingLastPathComponent(),
            sourceRoot: permissionedSourceRoot,
            kind: .generatedWire,
            expectedSourcePrefix: "Sources/SwanSpacesWire/",
            generatedTargetRoot: "Sources/SwanSpacesWire",
            diagnostics: &diagnostics
        )

        return .init(profileID: pins.id, diagnostics: diagnostics)
    }

    private static func verifyPublic(
        _ profileData: Data,
        profileURL: URL,
        sourceRoot: URL?
    ) -> ProtocolProfileVerificationReport {
        var diagnostics: [ProtocolProfileVerificationDiagnostic] = []
        let pins: PublicArtifactPins
        do {
            pins = try JSONDecoder().decode(PublicArtifactPins.self, from: profileData)
        } catch {
            return .init(profileID: publicProfileID, diagnostics: [.init(.malformedProfile, artifact: "profile")])
        }
        let expectedKeys: Set<String> = [
            "id", "referenceImplementationCommit", "petrelGeneratorCommit", "petrelCommit",
            "referenceArchiveSHA256", "petrelManifest", "petrelManifestSHA256",
            "lexiconManifest", "lexiconManifestSHA256",
            "generatedWireManifest", "generatedWireManifestSHA256",
            "inventorySemantics", "intentionalDivergences", "lexicons", "endpoints",
        ]
        let actualKeys = ((try? JSONSerialization.jsonObject(with: profileData)) as? [String: Any])
            .map { Set($0.keys) }
        if actualKeys != expectedKeys {
            diagnostics.append(.init(.malformedProfile, artifact: "profile"))
        }
        let profileBytesMatch =
            Hex.encode(SHA256.hash(data: profileData)) == expectedPublicProfileSHA256
        if ![
            pins.referenceImplementationCommit,
            pins.petrelGeneratorCommit,
            pins.petrelCommit,
        ].allSatisfy({ isLowercaseHex($0, count: 40) }) {
            diagnostics.append(.init(.invalidRevisionPin, artifact: "profile"))
        }
        if pins.referenceArchiveSHA256.map({ !isLowercaseHex($0, count: 64) }) ?? true {
            diagnostics.append(.init(.invalidChecksumPin, artifact: "reference archive"))
        }
        if pins.lexicons.count != 21 ||
            Set(pins.lexicons).count != 21 ||
            pins.endpoints.count != 19 ||
            Set(pins.endpoints).count != 19 ||
            pins.endpoints.contains(where: { $0.hasSuffix(".defs") }) {
            diagnostics.append(.init(.malformedProfile, artifact: "profile"))
        }
        if !profileBytesMatch || !hasExpectedPublicPins(pins) {
            diagnostics.append(.init(.immutableProfilePinMismatch, artifact: "profile"))
        }
        let publicSourceRoot = sourceRoot ??
            profileURL.deletingLastPathComponent().deletingLastPathComponent()
        if let name = pins.petrelManifest,
           let checksum = pins.petrelManifestSHA256,
           name == "PublicPetrelManifest.json",
           isLowercaseHex(checksum, count: 64) {
            let manifestURL = publicSourceRoot.appending(path: name)
            if isSymbolicLink(manifestURL) ||
                (try? Data(contentsOf: manifestURL, options: [.mappedIfSafe]))
                    .map({ Hex.encode(SHA256.hash(data: $0)) }) != checksum {
                diagnostics.append(.init(.immutableProfilePinMismatch, artifact: "Petrel manifest"))
            }
        } else {
            diagnostics.append(.init(.immutableProfilePinMismatch, artifact: "Petrel manifest"))
        }
        verifyManifest(
            name: pins.lexiconManifest,
            checksum: pins.lexiconManifestSHA256,
            expectedName: "\(publicProfileID).lexicons.sha256",
            profileDirectory: profileURL.deletingLastPathComponent(),
            sourceRoot: nil,
            kind: .lexicon,
            expectedSourcePrefix: "com/atproto/",
            generatedTargetRoot: nil,
            diagnostics: &diagnostics
        )
        verifyManifest(
            name: pins.generatedWireManifest,
            checksum: pins.generatedWireManifestSHA256,
            expectedName: "\(publicProfileID).generated-wire.sha256",
            profileDirectory: profileURL.deletingLastPathComponent(),
            sourceRoot: publicSourceRoot,
            kind: .generatedWire,
            expectedSourcePrefix: "Sources/SwanPublicWire/",
            generatedTargetRoot: "Sources/SwanPublicWire",
            diagnostics: &diagnostics
        )
        return .init(profileID: pins.id, diagnostics: diagnostics)
    }

    private enum ManifestKind: Equatable {
        case lexicon
        case generatedWire
    }

    private static func verifyManifest(
        name: String?,
        checksum: String?,
        expectedName: String,
        profileDirectory: URL,
        sourceRoot: URL?,
        kind: ManifestKind,
        expectedSourcePrefix: String,
        generatedTargetRoot: String?,
        diagnostics: inout [ProtocolProfileVerificationDiagnostic]
    ) {
        let artifact = kind == .lexicon ? "lexicon manifest" : "generated wire manifest"
        let missingCode: ProtocolProfileVerificationDiagnostic.Code = .missingArtifactPin
        guard let name, let checksum else {
            diagnostics.append(.init(missingCode, artifact: artifact))
            return
        }
        guard name == expectedName else {
            diagnostics.append(.init(.invalidArtifactName, artifact: artifact))
            return
        }
        guard isLowercaseHex(checksum, count: 64) else {
            diagnostics.append(.init(.invalidChecksumPin, artifact: artifact))
            return
        }

        let manifestData: Data
        let manifestURL = profileDirectory.appending(path: name)
        guard !isSymbolicLink(manifestURL) else {
            diagnostics.append(.init(
                kind == .lexicon ? .unreadableLexiconManifest : .unreadableGeneratedWireManifest,
                artifact: artifact
            ))
            return
        }
        do {
            manifestData = try Data(contentsOf: manifestURL, options: [.mappedIfSafe])
        } catch {
            diagnostics.append(.init(
                kind == .lexicon ? .unreadableLexiconManifest : .unreadableGeneratedWireManifest,
                artifact: artifact
            ))
            return
        }
        guard Hex.encode(SHA256.hash(data: manifestData)) == checksum else {
            diagnostics.append(.init(
                kind == .lexicon ? .lexiconManifestDigestMismatch : .generatedWireManifestDigestMismatch,
                artifact: artifact
            ))
            return
        }
        guard let manifestText = String(data: manifestData, encoding: .utf8),
              let entries = parseManifest(
                  manifestText,
                  kind: kind,
                  expectedSourcePrefix: expectedSourcePrefix
              ) else {
            diagnostics.append(.init(
                kind == .lexicon ? .malformedLexiconManifest : .malformedGeneratedWireManifest,
                artifact: artifact
            ))
            return
        }

        guard kind == .generatedWire, let sourceRoot else { return }
        guard let generatedTargetRoot else {
            diagnostics.append(.init(.malformedGeneratedWireManifest, artifact: artifact))
            return
        }
        verifyGeneratedWireSources(
            entries,
            sourceRoot: sourceRoot,
            generatedTargetRoot: generatedTargetRoot,
            diagnostics: &diagnostics
        )
    }

    private static func parseManifest(
        _ text: String,
        kind: ManifestKind,
        expectedSourcePrefix: String
    ) -> [ManifestEntry]? {
        guard text.unicodeScalars.allSatisfy({ $0.value != 13 }) else { return nil }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: true)
        guard !lines.isEmpty else { return nil }
        var entries: [ManifestEntry] = []
        var paths = Set<String>()
        for line in lines {
            let fields = line.split(separator: " ", omittingEmptySubsequences: false)
            guard fields.count == 3, fields[1].isEmpty,
                  isLowercaseHex(String(fields[0]), count: 64) else { return nil }
            let path = String(fields[2])
            let expectedSuffix = kind == .lexicon ? ".json" : ".swift"
            guard path.hasPrefix(expectedSourcePrefix), path.hasSuffix(expectedSuffix),
                  isSafeRelativePath(path), paths.insert(path).inserted else { return nil }
            entries.append(.init(checksum: String(fields[0]), path: path))
        }
        guard entries.map(\.path) == entries.map(\.path).sorted() else { return nil }
        return entries
    }

    private static func verifyGeneratedWireSources(
        _ entries: [ManifestEntry],
        sourceRoot: URL,
        generatedTargetRoot: String,
        diagnostics: inout [ProtocolProfileVerificationDiagnostic]
    ) {
        let canonicalRoot = sourceRoot.resolvingSymlinksInPath().standardizedFileURL
        let expectedPaths = Set(entries.map(\.path))
        var discoveredPaths = Set<String>()
        for entry in entries {
            let lexicalSource = canonicalRoot.appending(path: entry.path)
                .standardizedFileURL
            let source = lexicalSource
                .resolvingSymlinksInPath()
                .standardizedFileURL
            guard lexicalSource == source else {
                diagnostics.append(.init(.generatedWireSourceSymlink, artifact: "generated wire source"))
                continue
            }
            guard isWithin(source, root: canonicalRoot) else {
                diagnostics.append(.init(.generatedWireSourceOutsideRoot, artifact: "generated wire source"))
                continue
            }
            let sourceData: Data
            do {
                sourceData = try Data(contentsOf: source, options: [.mappedIfSafe])
            } catch {
                diagnostics.append(.init(.generatedWireSourceMissing, artifact: "generated wire source"))
                continue
            }
            guard Hex.encode(SHA256.hash(data: sourceData)) == entry.checksum else {
                diagnostics.append(.init(.generatedWireSourceChecksumMismatch, artifact: "generated wire source"))
                continue
            }
        }

        let wireRoot = canonicalRoot.appending(path: generatedTargetRoot, directoryHint: .isDirectory)
        if let enumerator = FileManager.default.enumerator(
            at: wireRoot,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) {
            while let candidate = enumerator.nextObject() as? URL {
                guard candidate.pathExtension == "swift" else { continue }
                let lexicalCandidate = candidate.standardizedFileURL
                let canonicalCandidate = lexicalCandidate.resolvingSymlinksInPath().standardizedFileURL
                guard lexicalCandidate == canonicalCandidate else {
                    diagnostics.append(.init(.generatedWireSourceSymlink, artifact: "generated wire source"))
                    continue
                }
                guard isWithin(canonicalCandidate, root: canonicalRoot) else {
                    diagnostics.append(.init(.generatedWireSourceOutsideRoot, artifact: "generated wire source"))
                    continue
                }
                let components = canonicalCandidate.pathComponents.dropFirst(canonicalRoot.pathComponents.count)
                discoveredPaths.insert(components.joined(separator: "/"))
            }
        }
        if discoveredPaths != expectedPaths {
            diagnostics.append(.init(.generatedWireSourceSetMismatch, artifact: "generated wire sources"))
        }
    }

    private static func isSafeRelativePath(_ path: String) -> Bool {
        guard !path.isEmpty, !path.hasPrefix("/"), !path.contains("\\") else { return false }
        return !path.split(separator: "/").contains(where: { $0.isEmpty || $0 == "." || $0 == ".." })
    }

    private static func isWithin(_ candidate: URL, root: URL) -> Bool {
        let rootComponents = root.pathComponents
        let candidateComponents = candidate.pathComponents
        return candidateComponents.starts(with: rootComponents) && candidateComponents.count > rootComponents.count
    }

    private static func isLowercaseHex(_ value: String, count: Int) -> Bool {
        value.utf8.count == count && value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
    }

    private static func isSymbolicLink(_ url: URL) -> Bool {
        (try? FileManager.default.destinationOfSymbolicLink(atPath: url.path)) != nil
    }

    private static func hasExpectedImmutablePins(_ pins: ArtifactPins) -> Bool {
        pins.id == stableProfileID &&
            pins.proposalCommit == expectedProposalCommit &&
            pins.referenceImplementationCommit == expectedReferenceImplementationCommit &&
            pins.petrelGeneratorCommit == expectedPetrelGeneratorCommit &&
            pins.petrelCommit == expectedPetrelCommit &&
            pins.migrationCompatibility == "additiveWithProducingBuildRestore" &&
            pins.crypto == .init(
                lthashBytes: 2_048,
                lthashHash: "BLAKE3-XOF",
                commitmentHash: "SHA-256",
                contentBinding: "DHKEM(P-256,HKDF-SHA256)/HMAC-SHA256"
            ) &&
            pins.permissionedDataIsEncrypted == false &&
            pins.oplogRetention == 10_000 &&
            pins.referenceArchiveSHA256 == expectedReferenceArchiveSHA256 &&
            pins.petrelManifest == "PetrelManifest.json" &&
            pins.petrelManifestSHA256 == expectedPetrelManifestSHA256 &&
            pins.lexiconManifest == "\(stableProfileID).lexicons.sha256" &&
            pins.lexiconManifestSHA256 == expectedLexiconManifestSHA256 &&
            pins.generatedWireManifest == "\(stableProfileID).generated-wire.sha256" &&
            pins.generatedWireManifestSHA256 == expectedGeneratedWireManifestSHA256 &&
            pins.endpoints == expectedEndpoints
    }

    private static func hasExpectedPublicPins(_ pins: PublicArtifactPins) -> Bool {
        pins.id == publicProfileID &&
            pins.referenceImplementationCommit == expectedPublicReferenceImplementationCommit &&
            pins.petrelGeneratorCommit == expectedPublicPetrelGeneratorCommit &&
            pins.petrelCommit == expectedPublicPetrelCommit &&
            pins.referenceArchiveSHA256 == expectedPublicReferenceArchiveSHA256 &&
            pins.petrelManifest == "PublicPetrelManifest.json" &&
            pins.petrelManifestSHA256 == expectedPublicPetrelManifestSHA256 &&
            pins.lexiconManifest == "\(publicProfileID).lexicons.sha256" &&
            pins.lexiconManifestSHA256 == expectedPublicLexiconManifestSHA256 &&
            pins.generatedWireManifest == "\(publicProfileID).generated-wire.sha256" &&
            pins.generatedWireManifestSHA256 == expectedPublicGeneratedWireManifestSHA256 &&
            pins.inventorySemantics == expectedPublicInventorySemantics &&
            pins.lexicons == expectedPublicLexicons &&
            pins.endpoints == expectedPublicEndpoints &&
            pins.intentionalDivergences.count == 2 &&
            pins.intentionalDivergences[0].endpoint == "com.atproto.sync.getRepo" &&
            pins.intentionalDivergences[0].referenceBehavior ==
                "Accepts an optional since revision for an incremental repository CAR." &&
            pins.intentionalDivergences[0].swanBehavior ==
                "Rejects a nonempty since until retained-history incremental CARs are implemented; it never returns a full CAR while claiming to honor since." &&
            pins.intentionalDivergences[1].endpoint == "com.atproto.sync.subscribeRepos" &&
            pins.intentionalDivergences[1].referenceBehavior ==
                "Parses the cursor query parameter tolerantly."
    }
}

public struct ReferenceSourcePin: Codable, Sendable, Equatable {
    public let repository: URL
    public let commit: String
    public let archiveSHA256: String?

    public init(
        repository: URL = URL(string: "https://github.com/bluesky-social/atproto")!,
        commit: String = "3f6c96d5d2d25438bd40fa89d6ecc37865f8e354",
        archiveSHA256: String? = "1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea"
    ) {
        self.repository = repository
        self.commit = commit
        self.archiveSHA256 = archiveSHA256
    }
}

/// A path-free status for the local Compose laboratory inputs.  The report is
/// deliberately suitable for CI logs: it identifies only the failed invariant,
/// never an operator-provided filesystem location or file contents.
public struct InteropLabPrerequisiteReport: Sendable, Equatable {
    public enum Diagnostic: String, Sendable, Equatable, Codable {
        case missingReferenceArchive
        case invalidReferenceArchive
        case missingReferenceSource
        case invalidReferenceSource
    }

    public let diagnostics: [Diagnostic]

    public init(diagnostics: [Diagnostic]) {
        self.diagnostics = diagnostics
    }

    public var isValid: Bool { diagnostics.isEmpty }
}

/// The intentionally small artifact emitted by the scenario runner before a
/// matrix execution. It describes only public pins and fault intent; request,
/// response, account, and credential values have no representation here.
public struct SanitizedScenarioArtifact: Codable, Sendable, Equatable {
    public let profileID: String
    public let proposalCommit: String
    public let referenceImplementationCommit: String
    public let scenario: String
    public let faultModes: [FaultMode]
    public let status: String
    public let fixturePolicy: String

    public init(scenario: String, faultModes: [FaultMode]) throws {
        let normalizedScenario = scenario.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedScenario.isEmpty,
              normalizedScenario.unicodeScalars.allSatisfy({
                  CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_")).contains($0)
              }) else {
            throw SwanError.malformed("scenario names must be non-empty ASCII identifiers")
        }
        profileID = OfflineProtocolProfileVerifier.stableProfileID
        proposalCommit = "b89d0b04495a62e0e22f1ab04c665a9c4e1c655d"
        referenceImplementationCommit = "3f6c96d5d2d25438bd40fa89d6ecc37865f8e354"
        self.scenario = normalizedScenario
        self.faultModes = faultModes
        status = "planned-not-executed"
        fixturePolicy = "summary-only; no passwords, bearer tokens, DPoP keys, refresh tokens, or recoverable account data"
    }
}

/// Offline checks shared by `swan lab validate` and the Compose launcher. The
/// cache is deliberately an explicit prerequisite: image builds unpack its
/// verified archive and never clone or download the TypeScript reference.
public enum InteropLaboratory {
    public static func validate(
        cacheDirectory: URL,
        pin: ReferenceSourcePin = ReferenceSourcePin()
    ) -> InteropLabPrerequisiteReport {
        let manager = FileManager.default
        let archive = cacheDirectory.appending(path: "atproto-\(pin.commit).tar.gz")
        let sourceRoot = cacheDirectory.appending(path: "atproto-\(pin.commit)", directoryHint: .isDirectory)
        var diagnostics: [InteropLabPrerequisiteReport.Diagnostic] = []

        guard let archiveSHA256 = pin.archiveSHA256,
              archiveSHA256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            return .init(diagnostics: [.invalidReferenceArchive])
        }
        guard manager.fileExists(atPath: archive.path) else {
            diagnostics.append(.missingReferenceArchive)
            return .init(diagnostics: diagnostics)
        }
        guard let data = try? Data(contentsOf: archive),
              SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == archiveSHA256 else {
            diagnostics.append(.invalidReferenceArchive)
            return .init(diagnostics: diagnostics)
        }

        var isDirectory: ObjCBool = false
        guard manager.fileExists(atPath: sourceRoot.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            diagnostics.append(.missingReferenceSource)
            return .init(diagnostics: diagnostics)
        }
        let requiredSourceFiles = [
            "package.json",
            "pnpm-lock.yaml",
            "services/pds/Dockerfile",
            "packages/pds/package.json",
        ]
        guard requiredSourceFiles.allSatisfy({ manager.fileExists(atPath: sourceRoot.appending(path: $0).path) }) else {
            diagnostics.append(.invalidReferenceSource)
            return .init(diagnostics: diagnostics)
        }
        return .init(diagnostics: diagnostics)
    }
}

public enum FaultMode: String, Codable, Sendable, CaseIterable {
    case offline
    case disconnected
    case delayed
    case duplicated
    case reordered
    case corrupted
}

public struct SanitizedFixture: Codable, Sendable, Equatable {
    public let scenario: String
    public let requestSummary: [String: String]
    public let responseSummary: [String: String]
    public let commitmentHex: String?
    public let expectedError: String?

    public init(
        scenario: String,
        requestSummary: [String: String],
        responseSummary: [String: String],
        commitmentHex: String?,
        expectedError: String?
    ) {
        self.scenario = FixtureSanitizer.safeIdentifier(scenario)
        self.requestSummary = FixtureSanitizer.sanitize(requestSummary)
        self.responseSummary = FixtureSanitizer.sanitize(responseSummary)
        self.commitmentHex = FixtureSanitizer.canonicalSHA256Hex(commitmentHex)
        self.expectedError = expectedError.map(FixtureSanitizer.errorCode)
    }

    private enum CodingKeys: String, CodingKey {
        case scenario
        case requestSummary
        case responseSummary
        case commitmentHex
        case expectedError
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            scenario: try container.decode(String.self, forKey: .scenario),
            requestSummary: try container.decode(
                [String: String].self,
                forKey: .requestSummary
            ),
            responseSummary: try container.decode(
                [String: String].self,
                forKey: .responseSummary
            ),
            commitmentHex: try container.decodeIfPresent(
                String.self,
                forKey: .commitmentHex
            ),
            expectedError: try container.decodeIfPresent(
                String.self,
                forKey: .expectedError
            )
        )
    }
}

public enum FixtureSanitizer {
    private static let forbiddenKeys: Set<String> = [
        "authorization", "access_token", "refresh_token", "password", "dpop", "private_key", "ikm",
    ]

    private static let forbiddenFragments: [String] = [
        "authorization", "access_token", "refresh_token", "password", "dpop", "private_key", "private-key",
        "ikm", "bearer", "token", "atproto-token", "secret", "proof", "jti",
    ]

    private static let permittedErrorCodes: Set<String> = [
        "AuthMissing",
        "CARInvalidLimits",
        "CARInvalidChunk",
        "CARByteLimitExceeded",
        "CARMalformedVarint",
        "CARNonCanonicalVarint",
        "CARMalformedHeader",
        "CARInvalidRootCount",
        "CARUnsupportedVersion",
        "CARMalformedFrame",
        "CARInvalidCID",
        "CARBlockCIDMismatch",
        "CARCommitBodyLimitExceeded",
        "CARRecordBodyLimitExceeded",
        "CARCommitDidNotVerify",
        "CARMalformedIndex",
        "CARNonCanonicalIndex",
        "CARDuplicateIndexEntry",
        "CARIndexEntryLimitExceeded",
        "CARUniqueBlockLimitExceeded",
        "CARInvalidRecordOrder",
        "CARInvalidRecordValue",
        "CARUnindexedBlocks",
        "CARInvalidExpectedWitness",
        "CARExpectedWitnessMismatch",
        "CARCommitmentMismatch",
        "CARStagingUnavailable",
        "CommitMissing",
        "CommitmentMismatch",
        "ContentBindingMismatch",
        "ContextSignatureMismatch",
        "FileFailure",
        "InteropFailure",
        "InvalidBlobResponse",
        "InvalidCommit",
        "InvalidOperation",
        "InvalidRequest",
        "InvalidResponse",
        "MissingCommitKey",
        "MissingCredential",
        "MissingJwt",
        "OperationMismatch",
        "RepoDeactivated",
        "RepoSuspended",
        "RepoTakendown",
        "ResponseTooLarge",
        "SpaceNotFound",
        "TransportFailure",
        "Unauthorized",
        "UnexpectedContentType",
        "UnexpectedRedirect",
        "ValueCIDMismatch",
        "ValueMissing",
        "RecoveryBindingMismatch",
        "RecoveryCASConflict",
        "RecoveryConflictingRequestReuse",
        "RecoveryCorruptReplica",
        "RecoveryCorruptStaging",
        "RecoveryEquivocation",
        "RecoveryExpiredSession",
        "RecoveryFailed",
        "RecoveryFreshnessMismatch",
        "RecoveryImportInProgress",
        "RecoveryIncompleteBlock",
        "RecoveryInvalidBinding",
        "RecoveryInvalidChunk",
        "RecoveryInvalidStatus",
        "RecoveryInvalidTimestamp",
        "RecoveryPoisonedSession",
        "RecoveryRejected",
        "RecoveryReceiverMismatch",
        "RecoveryStale",
        "RecoveryUnknownSession",
        "RecoveryVerificationRequired",
        "RetentionGapMissing",
        "full_repo_recovery_required",
        "temporarily_unavailable",
        "use_dpop_nonce",
    ]

    public static func sanitize(_ fields: [String: String]) -> [String: String] {
        var output: [String: String] = [:]
        for (key, value) in fields {
            let normalizedKey = key.lowercased()

            // A response's object-member names and raw header values are
            // peer-controlled. Persist the already-recorded JSON member count
            // and bounded categories, never their opaque spellings.
            if normalizedKey.hasPrefix("json-key-") {
                continue
            }
            if normalizedKey == "content-type"
                || normalizedKey == "request-content-type" {
                output[key] = contentTypeCategory(value)
                continue
            }
            if normalizedKey == "cache-control" {
                output[key] = cacheControlCategory(value)
                continue
            }
            if normalizedKey == "scenario"
                || normalizedKey == "host"
                || normalizedKey == "assertion" {
                output[key] = safeIdentifier(value)
                continue
            }

            let isKeySensitive = forbiddenKeys.contains(normalizedKey)
                || forbiddenFragments.contains(where: { normalizedKey.contains($0) })
                || shouldRedactValue(value)

            if isKeySensitive {
                output[key] = "<redacted>"
                continue
            }

            if containsBearerLikeOrJWT(value) {
                output[key] = "<redacted>"
            } else {
                output[key] = value
            }
        }
        return output
    }

    /// Accepts only the representation emitted by Swan's SHA-256 encoder.
    /// Uppercase, truncated, overlong, or non-hex peer values do not become
    /// fixture evidence.
    public static func canonicalSHA256Hex(_ value: String?) -> String? {
        guard let value,
              value.utf8.count == 64,
              value.utf8.allSatisfy({
                  (0x30 ... 0x39).contains($0) || (0x61 ... 0x66).contains($0)
              }) else {
            return nil
        }
        return value
    }

    /// Operator-selected labels are identifiers, not free-form fixture text.
    /// The fixed grammar also prevents paths, URLs, or line-oriented data from
    /// being smuggled into an artifact through a label field.
    public static func safeIdentifier(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1 ... 64).contains(trimmed.utf8.count),
              trimmed.unicodeScalars.allSatisfy({
                  $0.value <= 0x7f
                      && (CharacterSet.alphanumerics.contains($0)
                          || CharacterSet(charactersIn: "._-").contains($0))
              }),
              !shouldRedactValue(trimmed),
              !containsBearerLikeOrJWT(trimmed) else {
            return "<redacted>"
        }
        return trimmed
    }

    public static func artifactStatus(_ value: String) -> String {
        switch value {
        case "passed", "failed", "planned-not-executed":
            return value
        default:
            return "failed"
        }
    }

    public static func httpMethod(_ value: String) -> String {
        switch value.uppercased() {
        case "GET", "POST", "PUT", "DELETE", "PATCH":
            return value.uppercased()
        default:
            return "<redacted>"
        }
    }

    /// Remote error bodies are not evidence-bearing free text. Preserve only
    /// protocol codes that Swan understands, so an upstream host cannot
    /// reflect an opaque bearer value into a persisted fixture.
    public static func errorCode(_ value: String) -> String {
        if permittedErrorCodes.contains(value) {
            return value
        }
        if value.count == 7,
           value.hasPrefix("HTTP"),
           let status = Int(value.dropFirst(4)),
           (400 ... 599).contains(status) {
            return value
        }
        return "<redacted>"
    }

    private static func contentTypeCategory(_ value: String) -> String {
        let mediaType = value
            .split(separator: ";", maxSplits: 1)
            .first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() ?? ""
        switch mediaType {
        case "application/json":
            return "json"
        case "application/vnd.ipld.car":
            return "car"
        case "application/octet-stream":
            return "binary"
        case "application/x-www-form-urlencoded":
            return "form"
        case "text/html":
            return "html"
        default:
            return mediaType.hasSuffix("+json") ? "json" : "other"
        }
    }

    private static func cacheControlCategory(_ value: String) -> String {
        let directives = value.lowercased().split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if directives.contains(where: { $0 == "no-store" }) {
            return "no-store"
        }
        if directives.contains(where: { $0 == "no-cache" }) {
            return "no-cache"
        }
        if directives.contains(where: {
            $0.range(of: #"^(s-maxage|max-age)=[0-9]+$"#, options: .regularExpression) != nil
        }) {
            return "cacheable"
        }
        return "other"
    }

    private static func shouldRedactValue(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        let normalized = trimmed.lowercased()
        // Fixture values may originate from host labels or response error
        // strings.  Those fields are not semantic evidence, so redact them
        // when they contain credential-shaped or owner-only material rather
        // than relying on the caller to have chosen a safe field name.
        if forbiddenFragments.contains(where: { normalized.contains($0) }) {
            return true
        }
        // Hide values that look like hex digest identifiers when they are long.
        if trimmed.count >= 48,
           trimmed.count <= 80,
           trimmed.allSatisfy({
               ("0123456789abcdefABCDEF".contains($0)) && !trimmed.starts(with: "baf")
           }) {
            return true
        }
        return false
    }

    private static func containsBearerLikeOrJWT(_ value: String) -> Bool {
        let parts = value.split(separator: ".")
        guard parts.count == 3 else { return false }
        return parts.allSatisfy { part in
            let charset: Set<Character> = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
            guard part.count >= 10 else {
                return false
            }
            return part.allSatisfy(charset.contains)
        }
    }
}
