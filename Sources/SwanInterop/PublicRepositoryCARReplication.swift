import Crypto
import Foundation
import Petrel
import SwanOAuth
import SwanCore
import SwanPublicRepository
import SwanSQLite
import SwanStorage

/// Errors returned by the bounded public-repository replication seam.  The
/// remote response is treated as untrusted until the CAR parser, commit
/// verifier, and durable import transaction have all completed.
public enum PublicRepositoryCARReplicationError: Error, Sendable, Equatable {
    case repositoryUnavailable
    case invalidRepositoryDID
    case invalidRequestID
    case invalidLifetime
    case unexpectedStatus(Int)
    case unexpectedContentType
    case responseTooLarge
    case spoolUnavailable
}

/// Errors from the optional receiver-side public-blob promotion step. The
/// repository CAR is already durable when this step runs; each blob is still
/// fetched into an owner-only temporary file and adopted through the normal
/// content-addressed public namespace transaction.
public enum PublicRepositoryBlobPromotionError: Error, Sendable, Equatable {
    case invalidRepositoryDID
    case repositoryTooLarge
    case invalidCID
    case unexpectedStatus(Int)
    case unexpectedContentType
    case responseTooLarge
    case digestMismatch
    case spoolUnavailable
}

/// Stable, secret-free failure labels for the import artifact. The CLI must
/// not serialize `localizedDescription` or a reflected arbitrary error: those
/// strings can contain a remote URL, selector, database path, or future
/// sensitive context. This projection intentionally preserves only the
/// protocol/storage boundary that rejected the untrusted CAR.
public enum PublicRepositoryCARImportFailureCode {
    public static func code(for error: Error) -> String {
        switch error {
        case let error as PublicRepositoryDIDResolutionError:
            switch error {
            case .invalidRepositoryDID: return "InvalidRepositoryDID"
            case .missingSigningKey: return "MissingSigningKey"
            case .unsupportedSigningKey: return "UnsupportedSigningKey"
            case .identityMismatch: return "IdentityMismatch"
            case .pdsServiceMismatch: return "PDSServicesMismatch"
            }
        case let error as PublicRepositoryCARReplicationError:
            switch error {
            case .repositoryUnavailable: return "RepositoryUnavailable"
            case .invalidRepositoryDID: return "InvalidRepositoryDID"
            case .invalidRequestID: return "InvalidRequestID"
            case .invalidLifetime: return "InvalidLifetime"
            case .unexpectedStatus: return "UnexpectedStatus"
            case .unexpectedContentType: return "UnexpectedContentType"
            case .responseTooLarge: return "ResponseTooLarge"
            case .spoolUnavailable: return "SpoolUnavailable"
            }
        case let error as PublicRepositoryBlobPromotionError:
            switch error {
            case .invalidRepositoryDID: return "BlobInvalidRepositoryDID"
            case .repositoryTooLarge: return "BlobRepositoryTooLarge"
            case .invalidCID: return "BlobInvalidCID"
            case let .unexpectedStatus(status): return "BlobUnexpectedStatus_\(status)"
            case .unexpectedContentType: return "BlobUnexpectedContentType"
            case .responseTooLarge: return "BlobResponseTooLarge"
            case .digestMismatch: return "BlobDigestMismatch"
            case .spoolUnavailable: return "BlobSpoolUnavailable"
            }
        case let error as InteropHTTPError:
            switch error {
            case .invalidURL: return "HTTPInvalidURL"
            case .responseTooLarge: return "HTTPResponseTooLarge"
            case .unexpectedRedirect: return "HTTPUnexpectedRedirect"
            case .unexpectedContentType: return "HTTPUnexpectedContentType"
            case let .unexpectedStatus(status): return "HTTPUnexpectedStatus_\(status)"
            case .transportFailure: return "HTTPTransportFailure"
            case .fileFailure: return "HTTPFileFailure"
            }
        case let error as PublicRepositoryMutationStoreError:
            switch error {
            case .invalidRequest: return "MutationInvalidRequest"
            case .invalidRequestDigest: return "MutationInvalidRequestDigest"
            case .ownershipMismatch: return "MutationOwnershipMismatch"
            case .reservationMismatch: return "MutationReservationMismatch"
            case .conflictingRequestReuse: return "MutationConflictingRequestReuse"
            case .commitCASConflict: return "MutationCommitCASConflict"
            case .preparedMutationMismatch: return "MutationPreparedMismatch"
            case .publicBlobNotReachable: return "MutationPublicBlobNotReachable"
            case .corruptRepository: return "MutationCorruptRepository"
            case .repositoryNotInstalled: return "MutationRepositoryNotInstalled"
            case .revisionExhausted: return "MutationRevisionExhausted"
            }
        case let error as SQLiteRepositoryError:
            switch error {
            case .duplicateRequest: return "SQLiteDuplicateRequest"
            case .corruptDatabase: return "SQLiteCorruptDatabase"
            case .revisionOutOfRange: return "SQLiteRevisionOutOfRange"
            case .conflictingPublicFirehoseSourceKey: return "SQLiteConflictingPublicFirehoseSourceKey"
            }
        case let error as SwanError:
            switch error {
            case .invalidIdentifier: return "SwanInvalidIdentifier"
            case .invalidProfile: return "SwanInvalidProfile"
            case .unauthorized: return "SwanUnauthorized"
            case .conflict: return "SwanConflict"
            case .expired: return "SwanExpired"
            case .malformed: return "SwanMalformed"
            case .unavailable: return "SwanUnavailable"
            }
        case let error as PublicRepositoryImportStagingError:
            switch error {
            case .invalidBinding: return "InvalidBinding"
            case .invalidTimestamp: return "InvalidTimestamp"
            case .unknownSession: return "UnknownSession"
            case .expiredSession: return "ExpiredSession"
            case .consumedSession: return "ConsumedSession"
            case .importInProgress: return "ImportInProgress"
            case .poisonedSession: return "PoisonedSession"
            case .bindingMismatch: return "BindingMismatch"
            case .conflictingRequestReuse: return "ConflictingRequestReuse"
            case .duplicateBlockConflict: return "DuplicateBlockConflict"
            case .headerConflict: return "HeaderConflict"
            case .verificationRequired: return "VerificationRequired"
            case .repositoryNotInstalled: return "RepositoryNotInstalled"
            case .commitCASConflict: return "CommitCASConflict"
            case .importedCommitMismatch: return "ImportedCommitMismatch"
            case .corruptStaging: return "CorruptStaging"
            case .corruptRepository: return "CorruptRepository"
            }
        case let error as PublicRepositoryCARError:
            switch error {
            case .invalidChunkSize: return "CARInvalidChunkSize"
            case .invalidRootCID: return "CARInvalidRootCID"
            case .invalidBlockCID: return "CARInvalidBlockCID"
            case .blockCIDMismatch: return "CARBlockCIDMismatch"
            case .blockBodyLimitExceeded: return "CARBlockBodyLimitExceeded"
            case .byteLimitExceeded: return "CARByteLimitExceeded"
            case .blockLimitExceeded: return "CARBlockLimitExceeded"
            case .malformedVarint: return "CARMalformedVarint"
            case .nonCanonicalVarint: return "CARNonCanonicalVarint"
            case .malformedHeader: return "CARMalformedHeader"
            case .unsupportedVersion: return "CARUnsupportedVersion"
            case .invalidRootCount: return "CARInvalidRootCount"
            case .malformedFrame: return "CARMalformedFrame"
            case .duplicateBlockConflict: return "CARDuplicateBlockConflict"
            case .missingCommit: return "CARMissingCommit"
            case let .commit(commit): return "CARCommit_\(commitCode(commit))"
            case let .repository(repository): return "CARRepository_\(repositoryCode(repository))"
            }
        default:
            let description = error.localizedDescription.lowercased()
            if description.contains("constraint") {
                return "SQLiteConstraint"
            }
            if description.contains("no such table") {
                return "SQLiteMissingTable"
            }
            if description.contains("readonly") || description.contains("read-only") {
                return "SQLiteReadOnly"
            }
            if description.contains("locked") || description.contains("busy") {
                return "SQLiteBusy"
            }
            return "ImportFailed"
        }
    }

    private static func commitCode(_ error: PublicRepositoryCommitError) -> String {
        switch error {
        case .invalidDID: return "InvalidDID"
        case .invalidRevision: return "InvalidRevision"
        case .revisionNotIncreasing: return "RevisionNotIncreasing"
        case .invalidDataCID: return "InvalidDataCID"
        case .invalidCommitCID: return "InvalidCommitCID"
        case .invalidSchema: return "InvalidSchema"
        case .nonCanonicalCBOR: return "NonCanonicalCBOR"
        case .invalidSignature: return "InvalidSignature"
        case .unsupportedSigningAlgorithm: return "UnsupportedSigningAlgorithm"
        }
    }

    private static func repositoryCode(_ error: RepositoryMSTValidationError) -> String {
        switch error {
        case .unsupportedCID: return "UnsupportedCID"
        case .missingBlock: return "MissingBlock"
        case .blockCIDMismatch: return "BlockCIDMismatch"
        case .invalidNodeSchema: return "InvalidNodeSchema"
        case .invalidEntrySchema: return "InvalidEntrySchema"
        case .nonCanonicalNode: return "NonCanonicalNode"
        case .invalidCIDLink: return "InvalidCIDLink"
        case .invalidPrefixCompression: return "InvalidPrefixCompression"
        case .keysNotStrictlyIncreasing: return "KeysNotStrictlyIncreasing"
        case .invalidPath: return "InvalidPath"
        case .leafLayerMismatch: return "LeafLayerMismatch"
        case .subtreeOutOfRange: return "SubtreeOutOfRange"
        case .invalidLayer: return "InvalidLayer"
        case .invalidEmptyTopology: return "InvalidEmptyTopology"
        case .repeatedNode: return "RepeatedNode"
        case .missingRecordBlock: return "MissingRecordBlock"
        case .recordBlockCIDMismatch: return "RecordBlockCIDMismatch"
        case .recordBlockTooLarge: return "RecordBlockTooLarge"
        case .invalidRecordBlock: return "InvalidRecordBlock"
        case .nodeLimitExceeded: return "NodeLimitExceeded"
        case .entryLimitExceeded: return "EntryLimitExceeded"
        case .recordLimitExceeded: return "RecordLimitExceeded"
        case .cborDepthLimitExceeded: return "CBORDepthLimitExceeded"
        case .invalidReachableRepositoryByteBudget: return "InvalidReachableRepositoryByteBudget"
        case .reachableRepositoryByteLimitExceeded: return "ReachableRepositoryByteLimitExceeded"
        }
    }
}

/// Sanitized result for `swan lab import-public`.  It carries repository
/// commitments and counts only; no record path, value, token, or key bytes
/// are suitable for inclusion in a fixture.
public struct PublicRepositoryCARImportArtifact: Codable, Sendable, Equatable {
    public let profileID: String
    public let remoteHost: String
    public let repositoryDID: String
    public let httpStatus: Int?
    public let baseCommitCID: String?
    public let importedCommitCID: String?
    public let importedDataCID: String?
    public let importedRevision: String?
    public let reachableBlockCount: Int?
    public let recordCount: Int?
    public let promotedBlobCount: Int?
    public let status: String
    public let errorCode: String?

    public init(
        remoteHost: String,
        repositoryDID: String,
        httpStatus: Int?,
        baseCommitCID: String?,
        importedCommitCID: String?,
        importedDataCID: String?,
        importedRevision: String?,
        reachableBlockCount: Int?,
        recordCount: Int?,
        promotedBlobCount: Int? = nil,
        status: String,
        errorCode: String?
    ) {
        profileID = OfflineProtocolProfileVerifier.publicProfileID
        self.remoteHost = FixtureSanitizer.sanitize(["host": remoteHost])["host"] ?? "<redacted>"
        self.repositoryDID = FixtureSanitizer.sanitize(["did": repositoryDID])["did"] ?? "<redacted>"
        self.httpStatus = httpStatus
        self.baseCommitCID = baseCommitCID
        self.importedCommitCID = importedCommitCID
        self.importedDataCID = importedDataCID
        self.importedRevision = importedRevision
        self.reachableBlockCount = reachableBlockCount
        self.recordCount = recordCount
        self.promotedBlobCount = promotedBlobCount
        self.status = status
        self.errorCode = errorCode.map(FixtureSanitizer.errorCode)
    }
}

public struct PublicRepositoryBlobPromotionResult: Sendable, Equatable {
    public let referencedBlobCount: Int
    public let promotedBlobCount: Int

    public init(referencedBlobCount: Int, promotedBlobCount: Int) {
        self.referencedBlobCount = referencedBlobCount
        self.promotedBlobCount = promotedBlobCount
    }
}

/// A verifier adapter for the two public-key encodings used by the alpha's
/// repository implementations.  The key remains operator supplied or
/// locally resolved; this type deliberately does not fetch DID/PLC data.
public struct PermissionedDataPublicRepositoryCommitVerifier: @unchecked Sendable,
    PublicRepositoryCommitVerifier
{
    private let key: PermissionedDataJWTVerificationKey

    public let signingAlgorithm: PublicRepositorySigningAlgorithm
    public let verificationIdentity: String

    public init(key: PermissionedDataJWTVerificationKey) {
        self.key = key
        switch key {
        case let .p256(publicKey):
            signingAlgorithm = .p256
            verificationIdentity = "p256-sha256:\(Hex.encode(SHA256.hash(data: publicKey.x963Representation)))"
        case let .secp256k1PublicKey(bytes):
            signingAlgorithm = .secp256k1
            verificationIdentity = "secp256k1-sha256:\(Hex.encode(SHA256.hash(data: bytes)))"
        }
    }

    public func verify(
        signature: Data,
        unsignedCommitBytes: Data,
        did: String
    ) async throws {
        let algorithm: String = switch signingAlgorithm {
        case .p256: "ES256"
        case .secp256k1: "ES256K"
        }
        guard try key.verify(
            signature: signature,
            signingInput: unsignedCommitBytes,
            algorithm: algorithm
        ) else {
            throw PublicRepositoryCommitError.invalidSignature
        }
        // Keep the repository verifier's DID argument meaningful even though
        // key selection is intentionally completed before verification.
        guard (try? DID(didString: did)) != nil else {
            throw PublicRepositoryCommitError.invalidSchema
        }
    }
}

/// A bounded file-backed source used after a streaming HTTP download.  The
/// CAR parser consumes at most one chunk at a time, so a large repository is
/// never accumulated in Swift heap memory.
public actor FilePublicRepositoryCARByteSource: PublicRepositoryCARByteSource {
    private let handle: FileHandle

    public init(url: URL) throws {
        handle = try FileHandle(forReadingFrom: url)
    }

    deinit {
        try? handle.close()
    }

    public func read(maximumBytes: Int) async throws -> Data? {
        guard (1 ... 4 * 1_024 * 1_024).contains(maximumBytes) else {
            throw PublicRepositoryCARReplicationError.responseTooLarge
        }
        let bytes = try handle.read(upToCount: maximumBytes) ?? Data()
        return bytes.isEmpty ? nil : bytes
    }

    public func close() throws {
        try handle.close()
    }
}

/// The durable remote public-repository import path used by the laboratory.
/// It intentionally uses `com.atproto.sync.getRepo`, which is the public
/// repository endpoint implemented by the pinned reference PDS even while
/// that branch's permissioned `space.getRepo` remains unimplemented.
public struct RemotePublicRepositoryCARImporter: Sendable {
    public let client: InteropXRPCClient
    public let limits: PublicRepositoryLimits
    /// Shared disk admission for the remote CAR spool. A missing admission
    /// is fail-closed so this operator-only seam cannot bypass public-read
    /// resource bounds by creating an uncoordinated temporary file.
    public let spoolAdmission: PublicRepositorySpoolAdmission?

    public init(
        client: InteropXRPCClient,
        limits: PublicRepositoryLimits = .standard,
        spoolAdmission: PublicRepositorySpoolAdmission? = nil
    ) {
        self.client = client
        self.limits = limits
        self.spoolAdmission = spoolAdmission
    }

    public func importRepository(
        did: String,
        database: SQLiteAccountDatabase,
        verifier: any PublicRepositoryCommitVerifier,
        requestID: String,
        lifetime: Int64 = 300,
        now: Int64 = Int64(Date().timeIntervalSince1970)
    ) async throws -> CommittedPublicRepositoryImport {
        guard (try? DID(didString: did)) != nil else {
            throw PublicRepositoryCARReplicationError.invalidRepositoryDID
        }
        guard !requestID.isEmpty,
              requestID.utf8.count <= 512,
              !requestID.contains("\0") else {
            throw PublicRepositoryCARReplicationError.invalidRequestID
        }
        guard lifetime > 0, lifetime <= 24 * 60 * 60,
              now >= 0, now <= Int64.max - lifetime else {
            throw PublicRepositoryCARReplicationError.invalidLifetime
        }
        guard let current = try await database.loadPublicRepositoryState() else {
            throw PublicRepositoryCARReplicationError.repositoryUnavailable
        }
        guard current.did == did else {
            throw PublicRepositoryCARReplicationError.repositoryUnavailable
        }
        guard let spoolAdmission,
              let spoolLease = spoolAdmission.reserve(
                  accountDID: did,
                  maximumBytes: limits.maximumCARBytes
              ) else {
            throw PublicRepositoryCARReplicationError.spoolUnavailable
        }
        defer { spoolLease.release() }

        let temporaryURL = FileManager.default.temporaryDirectory
            .appending(path: "swan-public-repository-import-\(UUID().uuidString).car")
        defer { try? FileManager.default.removeItem(at: temporaryURL) }

        let response = try await client.stream(
            "com.atproto.sync.getRepo",
            query: ["did": did],
            to: temporaryURL,
            maximumResponseBytes: limits.maximumCARBytes
        )
        guard (200 ... 299).contains(response.status) else {
            throw PublicRepositoryCARReplicationError.unexpectedStatus(response.status)
        }
        guard let contentType = response.header("content-type")?.lowercased(),
              contentType.contains("application/vnd.ipld.car")
                || contentType.contains("application/octet-stream") else {
            throw PublicRepositoryCARReplicationError.unexpectedContentType
        }

        let requestDigest = Data(SHA256.hash(data: Data(
            "swan.public-sync.getRepo.v1\0\(client.http.baseURL.absoluteString)\0\(did)\0\(current.commitCID.string)"
                .utf8
        )))
        let binding = try PublicRepositoryImportBinding(
            requestID: requestID,
            requestDigest: requestDigest,
            accountDID: did,
            expectedBaseCommitCID: current.commitCID,
            verifierIdentity: verifier.verificationIdentity,
            policy: PublicRepositoryImportPolicy(limits: limits)
        )
        let source = try FilePublicRepositoryCARByteSource(url: temporaryURL)
        do {
            let result = try await SQLitePublicRepositoryImportCoordinator(
                database: database
            ).importRepository(
                from: source,
                binding: binding,
                verifier: verifier,
                createdAt: now,
                expiresAt: now + lifetime
            )
            try await source.close()
            return result
        } catch {
            try? await source.close()
            throw error
        }
    }

    /// Resolves the repository signing key from an authenticated PLC state,
    /// then delegates to the same bounded CAR/import transaction. Resolution
    /// happens before the request binding and no network work occurs inside
    /// SQLite publication.
    public func importRepository(
        did: String,
        database: SQLiteAccountDatabase,
        keyResolver: any PublicRepositoryCommitKeyResolving,
        requestID: String,
        lifetime: Int64 = 300,
        now: Int64 = Int64(Date().timeIntervalSince1970)
    ) async throws -> CommittedPublicRepositoryImport {
        let verifier = try await keyResolver.resolveCommitVerifier(for: did)
        return try await importRepository(
            did: did,
            database: database,
            verifier: verifier,
            requestID: requestID,
            lifetime: lifetime,
            now: now
        )
    }
}

/// Fetches raw-CID values from a verified public repository and adopts them in
/// the receiver's public blob namespace. Network I/O completes before the
/// SQLite CAS transaction starts; the temporary file and the store's bounded
/// streaming source keep memory independent of blob size.
public struct RemotePublicRepositoryBlobPromoter: Sendable {
    public let client: InteropXRPCClient
    public let limits: PublicRepositoryLimits
    /// The HTTP response and the receiver's adoption spool coexist for one
    /// blob, so the same lease is held until both the source descriptor and
    /// temporary file are closed.
    public let spoolAdmission: PublicRepositorySpoolAdmission?

    public init(
        client: InteropXRPCClient,
        limits: PublicRepositoryLimits = .standard,
        spoolAdmission: PublicRepositorySpoolAdmission? = nil
    ) {
        self.client = client
        self.limits = limits
        self.spoolAdmission = spoolAdmission
    }

    public func promoteReferencedBlobs(
        in database: SQLiteAccountDatabase,
        did: String
    ) async throws -> PublicRepositoryBlobPromotionResult {
        guard (try? DID(didString: did)) != nil else {
            throw PublicRepositoryBlobPromotionError.invalidRepositoryDID
        }
        guard await database.publicRepositoryDID() == did else {
            throw PublicRepositoryBlobPromotionError.invalidRepositoryDID
        }
        let referenced: [CID]
        do {
            referenced = try await database.publicRepositoryBlobCIDs()
        } catch PublicRepositoryReadError.resourceLimitExceeded {
            throw PublicRepositoryBlobPromotionError.repositoryTooLarge
        } catch {
            throw PublicRepositoryBlobPromotionError.unexpectedStatus(0)
        }
        var promoted = 0
        for cid in referenced {
            guard cid.codec == .raw,
                  cid.multihash.algorithm == Multihash.sha256Code,
                  cid.multihash.length == Multihash.sha256Length else {
                throw PublicRepositoryBlobPromotionError.invalidCID
            }
            if try await database.publicBlobExists(cid: cid.string) {
                continue
            }
            let reservation = limits.maximumCARBytes
                .multipliedReportingOverflow(by: 2)
            guard let spoolAdmission,
                  !reservation.overflow,
                  let spoolLease = spoolAdmission.reserve(
                      accountDID: did,
                      maximumBytes: reservation.partialValue
                  ) else {
                throw PublicRepositoryBlobPromotionError.spoolUnavailable
            }
            let temporaryURL = FileManager.default.temporaryDirectory
                .appending(path: "swan-public-blob-promotion-\(UUID().uuidString).blob")
            defer {
                try? FileManager.default.removeItem(at: temporaryURL)
                spoolLease.release()
            }
            let path: String
            do {
                path = try client.xrpcPath(
                    "com.atproto.sync.getBlob",
                    query: ["cid": cid.string, "did": did]
                )
            } catch {
                throw PublicRepositoryBlobPromotionError.invalidCID
            }
            let response: InteropHTTPResponse
            do {
                response = try await client.http.executeStreaming(
                    method: .get,
                    path: path,
                    headers: [
                        "Accept": "application/octet-stream, application/json, */*",
                    ],
                    to: temporaryURL,
                    maximumResponseBytes: limits.maximumCARBytes
                )
            } catch let error as InteropHTTPError {
                switch error {
                case .responseTooLarge: throw PublicRepositoryBlobPromotionError.responseTooLarge
                case let .unexpectedStatus(status):
                    throw PublicRepositoryBlobPromotionError.unexpectedStatus(status)
                case .unexpectedContentType: throw PublicRepositoryBlobPromotionError.unexpectedContentType
                default: throw PublicRepositoryBlobPromotionError.unexpectedStatus(0)
                }
            } catch {
                throw PublicRepositoryBlobPromotionError.unexpectedStatus(0)
            }
            guard (200 ... 299).contains(response.status) else {
                throw PublicRepositoryBlobPromotionError.unexpectedStatus(response.status)
            }
            guard let responseContentType = response.header("content-type"),
                  !responseContentType.lowercased().contains("application/json") else {
                throw PublicRepositoryBlobPromotionError.unexpectedContentType
            }
            let mimeType = responseContentType
                .split(separator: ";", maxSplits: 1)
                .first
                .map(String.init)
                ?? "application/octet-stream"
            let source = try FilePublicRepositoryCARByteSource(url: temporaryURL)
            do {
                let reference = try await database.putStreaming(
                    namespace: .public,
                    mimeType: mimeType,
                    maximumBytes: limits.maximumCARBytes
                ) { sink in
                    while let chunk = try await source.read(maximumBytes: 64 * 1_024) {
                        try await sink(chunk)
                    }
                }
                try await source.close()
                guard reference.namespace == .public, reference.cid == cid.string else {
                    throw PublicRepositoryBlobPromotionError.digestMismatch
                }
                promoted += 1
            } catch {
                try? await source.close()
                if let error = error as? PublicRepositoryBlobPromotionError {
                    throw error
                }
                throw PublicRepositoryBlobPromotionError.digestMismatch
            }
        }
        return PublicRepositoryBlobPromotionResult(
            referencedBlobCount: referenced.count,
            promotedBlobCount: promoted
        )
    }
}
