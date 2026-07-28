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
        self.status = status
        self.errorCode = errorCode.map { FixtureSanitizer.sanitize(["error": $0])["error"] ?? "<redacted>" }
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

    public init(
        client: InteropXRPCClient,
        limits: PublicRepositoryLimits = .standard
    ) {
        self.client = client
        self.limits = limits
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
