import Foundation
import Petrel
import PetrelCrypto
import SwanAccounts
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage

/// Deterministic laboratory-only mutation applied after a bounded recovery
/// response has been spooled and before the normal streaming verifier sees it.
/// Production callers use the default `.none`; acceptance runs use
/// `.corruptLastByte` to prove a bad CAR cannot replace the durable head.
public enum PermissionedRemoteReplicaSourceFault: Sendable, Equatable {
    case none
    case corruptLastByte

    public func apply(to fileURL: URL) throws {
        guard self == .corruptLastByte else { return }
        let handle: FileHandle
        do {
            handle = try FileHandle(forUpdating: fileURL)
        } catch {
            throw InteropHTTPError.fileFailure
        }
        defer { try? handle.close() }
        do {
            let length = try handle.seekToEnd()
            guard length > 0 else { throw InteropHTTPError.fileFailure }
            try handle.seek(toOffset: length - 1)
            guard let byte = try handle.read(upToCount: 1), byte.count == 1 else {
                throw InteropHTTPError.fileFailure
            }
            try handle.seek(toOffset: length - 1)
            try handle.write(contentsOf: Data([byte[byte.startIndex] ^ 0x01]))
            try handle.synchronize()
        } catch let error as InteropHTTPError {
            throw error
        } catch {
            throw InteropHTTPError.fileFailure
        }
    }
}

/// A live HTTP source for durable permissioned-replica recovery.  The
/// provider performs two requests: first it fetches and checks the source's
/// current signed commit, then it opens the CAR stream from the same
/// configured origin and repository.  The orchestrator still performs the
/// final CAR/context/content-binding checks before publication.
///
/// Scope of the first request.  It yields a *freshness* witness, not an
/// independent authority.  The witness is fetched from the same configured
/// origin that then serves the CAR, so it cannot corroborate that origin —
/// an origin that lies about the CAR can serve a matching lie here.
///
/// Scope of the commit checks.  `verifyLatestCommit` authenticates the signed
/// tuple (space, author, rev, ikm) plus knowledge of the IKM.  It does not
/// authenticate the content commitment: the commitment is outside
/// `SpaceCommitCodec.contextSigningBytes`, and the IKM travels in the clear
/// in the same commit block, so a substituted commitment with a recomputed
/// MAC passes both checks under the author's original signature.  Exact-
/// content integrity is delegated to the pinned HTTPS source origin, bounded
/// downstream by the equivocation / high-water checks in
/// `SQLitePermissionedRemoteReplicaRecovery`.  See the F02 note in
/// `SpaceCARCodec.verifyStreamingRecovery` and `docs/threat-boundaries.md`.
public struct PermissionedRemoteReplicaHTTPSourceProvider:
    PermissionedRemoteReplicaSourceProvider, Sendable
{
    public let host: LiveInteropHost
    public let temporaryDirectory: URL
    public let spoolAdmission: PublicRepositorySpoolAdmission
    public let limits: SpaceCARRecoveryLimits
    public let fault: PermissionedRemoteReplicaSourceFault

    public init(
        host: LiveInteropHost,
        temporaryDirectory: URL = FileManager.default.temporaryDirectory,
        spoolAdmission: PublicRepositorySpoolAdmission,
        limits: SpaceCARRecoveryLimits = .standard,
        fault: PermissionedRemoteReplicaSourceFault = .none
    ) throws {
        guard let baseComponents = URLComponents(
            url: host.client.http.baseURL,
            resolvingAgainstBaseURL: false
        ),
        baseComponents.path.isEmpty || baseComponents.path == "/",
        baseComponents.query == nil,
        baseComponents.fragment == nil,
        baseComponents.user == nil,
        baseComponents.password == nil,
        PermissionedRemoteReplicaSourceIdentity.canonicalOrigin(
            host.client.http.baseURL
        ) != nil else {
            throw InteropHTTPError.invalidURL
        }
        self.host = host
        self.temporaryDirectory = temporaryDirectory
        self.spoolAdmission = spoolAdmission
        self.limits = limits
        self.fault = fault
        try FileManager.default.createDirectory(
            at: temporaryDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    public func openPermissionedRemoteReplicaSource(
        target: PermissionedRemoteReplicaTarget
    ) async throws -> PermissionedRemoteReplicaSourceSession {
        guard let verificationKey = host.permissionedCommitVerificationKey else {
            throw InteropHTTPError.transportFailure
        }

        let latestQuery = [
            "repo": target.repositoryDID,
            "space": target.space.rawValue,
        ]
        let latestPath = try host.client.xrpcPath(
            "com.atproto.space.getLatestCommit",
            query: latestQuery
        )
        let latestAuthorization = try await authorization(
            path: latestPath,
            provider: host.authorizationProvider,
            fallback: host.authorization
        )
        let latest = try await host.client.query(
            "com.atproto.space.getLatestCommit",
            query: latestQuery,
            authorization: latestAuthorization
        )
        guard (200 ... 299).contains(latest.status),
              latest.header("content-type")?.lowercased().contains("json") == true else {
            throw InteropHTTPError.unexpectedStatus(latest.status)
        }
        let output = try StrictJSON.decode(
            ComAtprotoSpaceGetLatestCommit.Output.self,
            from: latest.body
        )
        let commit = output.commit
        let freshness = try verifyLatestCommit(
            commit,
            target: target,
            verificationKey: verificationKey
        )
        let sourceIdentity = try PermissionedRemoteReplicaSourceIdentity(
            origin: host.client.http.baseURL,
            repositoryDID: target.repositoryDID,
            verifierIdentity: verificationKey.recoveryVerifierIdentity
        )
        guard let lease = spoolAdmission.reserve(
            accountDID: target.receiverDID,
            maximumBytes: limits.maximumCARBytes
        ) else {
            throw InteropHTTPError.responseTooLarge
        }

        let spoolURL = temporaryDirectory.appending(
            path: "swan-permissioned-recovery-\(UUID().uuidString).car"
        )
        do {
            let carQuery = [
                "repo": target.repositoryDID,
                "space": target.space.rawValue,
            ]
            let carPath = try host.client.xrpcPath(
                "com.atproto.space.getRepo",
                query: carQuery
            )
            let carAuthorization = try await authorization(
                path: carPath,
                provider: host.authorizationProvider,
                fallback: host.authorization
            )
            let response = try await host.client.stream(
                "com.atproto.space.getRepo",
                query: carQuery,
                authorization: carAuthorization,
                to: spoolURL,
                maximumResponseBytes: limits.maximumCARBytes
            )
            guard (200 ... 299).contains(response.status),
                  response.header("content-type")?.lowercased()
                    .contains("application/vnd.ipld.car") == true else {
                throw InteropHTTPError.unexpectedStatus(response.status)
            }
            try fault.apply(to: spoolURL)
            let source = try PermissionedRemoteReplicaFileSource(
                fileURL: spoolURL
            )
            return try PermissionedRemoteReplicaSourceSession(
                identity: sourceIdentity,
                verificationKey: verificationKey,
                freshnessWitness: freshness,
                source: source,
                closeSource: {
                    await source.close()
                    try? FileManager.default.removeItem(at: spoolURL)
                    lease.release()
                }
            )
        } catch {
            lease.release()
            try? FileManager.default.removeItem(at: spoolURL)
            throw error
        }
    }

    private func authorization(
        path: String,
        provider: InteropAuthorizationProvider?,
        fallback: InteropAuthorization
    ) async throws -> InteropAuthorization {
        guard let provider,
              let target = URL(
                string: path,
                relativeTo: host.client.http.baseURL
            )?.absoluteURL else {
            return fallback
        }
        return try await provider(.get, target, nil)
    }

    private func verifyLatestCommit(
        _ commit: ComAtprotoSpaceDefs.SignedCommit,
        target: PermissionedRemoteReplicaTarget,
        verificationKey: PermissionedDataJWTVerificationKey
    ) throws -> PermissionedRemoteReplicaFreshnessWitness {
        guard commit.ver == 1,
              commit.hash.data.count == 32,
              commit.ikm.data.count == 32,
              commit.sig.data.count == 64,
              commit.mac.data.count == 32 else {
            throw InteropHTTPError.unexpectedStatus(502)
        }
        let context = try SpaceCommitContext(
            space: target.space,
            author: target.repositoryDID,
            rev: commit.rev.toString(),
            ikm: commit.ikm.data
        )
        let envelope = SpaceCommitEnvelope(
            ver: commit.ver,
            context: context,
            contextSignature: commit.sig.data,
            contentBinding: commit.mac.data,
            commitment: commit.hash.data
        )
        let algorithm: String = switch verificationKey {
        case .p256: "ES256"
        case .secp256k1PublicKey: "ES256K"
        }
        guard try verificationKey.verify(
            signature: envelope.contextSignature,
            signingInput: try SpaceCommitCodec.contextSigningBytes(context),
            algorithm: algorithm
        ),
        SpaceCommitCodec.verifyContentBinding(envelope) else {
            throw InteropHTTPError.unexpectedStatus(502)
        }
        return try PermissionedRemoteReplicaFreshnessWitness(
            wireRevision: commit.rev,
            commitment: commit.hash.data
        )
    }
}

/// Owner-only, one-shot CAR source used by the HTTP provider.  Keeping the
/// descriptor behind an actor prevents a verifier and cleanup callback from
/// racing a close or accidentally reading a second time.
private actor PermissionedRemoteReplicaFileSource:
    SpaceCARRecoveryByteSource
{
    private var handle: FileHandle?

    init(fileURL: URL) throws {
        handle = try FileHandle(forReadingFrom: fileURL)
    }

    func read(maximumBytes: Int) throws -> Data? {
        guard (1 ... SpaceCARRecoveryLimits.maximumChunkBytes)
            .contains(maximumBytes),
            let handle else {
            throw InteropHTTPError.fileFailure
        }
        return try handle.read(upToCount: maximumBytes)
    }

    func close() {
        guard let handle else { return }
        self.handle = nil
        try? handle.close()
    }
}
