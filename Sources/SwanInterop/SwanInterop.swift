import Foundation
import Crypto
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
    public static let stableProfileID = "permissioned-data-0016-2026-07-03"
    public static let publicProfileID = "public-data-testing-2026-07-27"

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
        let lexiconManifest: String?
        let lexiconManifestSHA256: String?
        let generatedWireManifest: String?
        let generatedWireManifestSHA256: String?
        let intentionalDivergences: [Divergence]
        let endpoints: [String]
    }

    private struct ManifestEntry: Equatable {
        let checksum: String
        let path: String
    }

    // This verifier deliberately supports exactly one immutable profile. Shape
    // validation alone would let a modified JSON file substitute a different
    // well-formed commit or manifest digest and still report success.
    private static let expectedProposalCommit = "1caad93dbb1f445396f6abf3b97eb4040345e78e"
    private static let expectedReferenceImplementationCommit = "3f6c96d5d2d25438bd40fa89d6ecc37865f8e354"
    private static let expectedPetrelGeneratorCommit = "d011ccf0029457434e659ec48c8024baa7b5c4e4"
    private static let expectedPetrelCommit = "db84b2c9788aa38000ee3f134e21feffa8f351cd"
    private static let expectedReferenceArchiveSHA256 = "1924ced5c07fb0ae5d8f13f0911bcbd2efc66e9460e463e9d8da10b94e8215ea"
    private static let expectedLexiconManifestSHA256 = "9d36b3bf54e8c307b460dabaf93411bd75be44ba1737f29b13592b4b997b899f"
    private static let expectedGeneratedWireManifestSHA256 = "c1d5697f351a4209c7f8a9faaf460d423f9f44f37845ae2c92e150e78c552609"
    private static let expectedPublicLexiconManifestSHA256 = "bd94660a2c2c05fc23185059329194ff6c29635f74ce2efcf97351c1be98fe97"
    private static let expectedPublicGeneratedWireManifestSHA256 = "c68177a315f6a3d6f01419f48be5e0beedf76d1e4ae21ebe5de52ac49ad80d3b"
    private static let expectedEndpoints = [
        "com.atproto.space.applyWrites",
        "com.atproto.space.createRecord",
        "com.atproto.space.deleteRecord",
        "com.atproto.space.getBlob",
        "com.atproto.space.getDelegationToken",
        "com.atproto.space.getLatestCommit",
        "com.atproto.space.getRecord",
        "com.atproto.space.getRepo",
        "com.atproto.space.getSpace",
        "com.atproto.space.getSpaceCredential",
        "com.atproto.space.listRecords",
        "com.atproto.space.listRepoOps",
        "com.atproto.space.listRepos",
        "com.atproto.space.listSpaces",
        "com.atproto.space.notifySpaceDeleted",
        "com.atproto.space.notifyWrite",
        "com.atproto.space.putRecord",
        "com.atproto.space.registerNotify",
        "com.atproto.simplespace.addMember",
        "com.atproto.simplespace.checkUserAccess",
        "com.atproto.simplespace.createSpace",
        "com.atproto.simplespace.deleteSpace",
        "com.atproto.simplespace.listMembers",
        "com.atproto.simplespace.removeMember",
        "com.atproto.simplespace.updateSpace",
    ]
    private static let expectedPublicEndpoints = [
        "com.atproto.repo.applyWrites",
        "com.atproto.repo.createRecord",
        "com.atproto.repo.deleteRecord",
        "com.atproto.repo.describeRepo",
        "com.atproto.repo.getRecord",
        "com.atproto.repo.listRecords",
        "com.atproto.repo.putRecord",
        "com.atproto.repo.uploadBlob",
        "com.atproto.sync.getBlob",
        "com.atproto.sync.getLatestCommit",
        "com.atproto.sync.getRepo",
        "com.atproto.sync.getRepoStatus",
    ]

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
        guard hasExpectedPublicPins(pins),
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
              entries.count == 14 else {
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
            "lexiconManifest", "lexiconManifestSHA256", "generatedWireManifest",
            "generatedWireManifestSHA256", "intentionalDivergences",
            "compatibilityExceptions", "endpoints",
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
        if !hasExpectedImmutablePins(pins) {
            diagnostics.append(.init(.immutableProfilePinMismatch, artifact: "profile"))
        }
        do {
            _ = try ProtocolProfile(data: profileData)
        } catch {
            diagnostics.append(.init(.malformedProfile, artifact: "profile"))
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
            sourceRoot: sourceRoot ?? profileURL
                .deletingLastPathComponent()
                .deletingLastPathComponent(),
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
            "referenceArchiveSHA256", "lexiconManifest", "lexiconManifestSHA256",
            "generatedWireManifest", "generatedWireManifestSHA256",
            "intentionalDivergences", "endpoints",
        ]
        let actualKeys = ((try? JSONSerialization.jsonObject(with: profileData)) as? [String: Any])
            .map { Set($0.keys) }
        if actualKeys != expectedKeys {
            diagnostics.append(.init(.malformedProfile, artifact: "profile"))
        }
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
        if !hasExpectedPublicPins(pins) {
            diagnostics.append(.init(.immutableProfilePinMismatch, artifact: "profile"))
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
            sourceRoot: sourceRoot ?? profileURL.deletingLastPathComponent().deletingLastPathComponent(),
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
            pins.migrationCompatibility == "destructiveBeforeAlpha" &&
            pins.crypto == .init(
                lthashBytes: 2_048,
                lthashHash: "BLAKE3-XOF",
                commitmentHash: "SHA-256",
                contentBinding: "HKDF-Expand/HMAC-SHA-256"
            ) &&
            pins.permissionedDataIsEncrypted == false &&
            pins.oplogRetention == 10_000 &&
            pins.referenceArchiveSHA256 == expectedReferenceArchiveSHA256 &&
            pins.lexiconManifest == "\(stableProfileID).lexicons.sha256" &&
            pins.lexiconManifestSHA256 == expectedLexiconManifestSHA256 &&
            pins.generatedWireManifest == "\(stableProfileID).generated-wire.sha256" &&
            pins.generatedWireManifestSHA256 == expectedGeneratedWireManifestSHA256 &&
            pins.endpoints == expectedEndpoints
    }

    private static func hasExpectedPublicPins(_ pins: PublicArtifactPins) -> Bool {
        pins.id == publicProfileID &&
            pins.referenceImplementationCommit == expectedReferenceImplementationCommit &&
            pins.petrelGeneratorCommit == expectedPetrelGeneratorCommit &&
            pins.petrelCommit == expectedPetrelCommit &&
            pins.referenceArchiveSHA256 == expectedReferenceArchiveSHA256 &&
            pins.lexiconManifest == "\(publicProfileID).lexicons.sha256" &&
            pins.lexiconManifestSHA256 == expectedPublicLexiconManifestSHA256 &&
            pins.generatedWireManifest == "\(publicProfileID).generated-wire.sha256" &&
            pins.generatedWireManifestSHA256 == expectedPublicGeneratedWireManifestSHA256 &&
            pins.endpoints == expectedPublicEndpoints &&
            pins.intentionalDivergences.count == 1 &&
            pins.intentionalDivergences.first?.endpoint == "com.atproto.sync.getRepo" &&
            pins.intentionalDivergences.first?.referenceBehavior ==
                "Accepts an optional since revision for an incremental repository CAR." &&
            pins.intentionalDivergences.first?.swanBehavior ==
                "Rejects a nonempty since until retained-history incremental CARs are implemented; it never returns a full CAR while claiming to honor since."
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
        proposalCommit = "1caad93dbb1f445396f6abf3b97eb4040345e78e"
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
}

public enum FixtureSanitizer {
    private static let forbiddenKeys: Set<String> = [
        "authorization", "access_token", "refresh_token", "password", "dpop", "private_key", "ikm",
    ]

    private static let forbiddenFragments: [String] = [
        "authorization", "access_token", "refresh_token", "password", "dpop", "private_key", "private-key",
        "ikm", "bearer", "token", "atproto-token", "secret", "proof", "jti",
    ]

    public static func sanitize(_ fields: [String: String]) -> [String: String] {
        var output: [String: String] = [:]
        for (key, value) in fields {
            let normalizedKey = key.lowercased()
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

    private static func shouldRedactValue(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
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
