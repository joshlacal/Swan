import Foundation
import Petrel
import SwanAccounts
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage

/// Deterministic laboratory-only mutation applied after a bounded recovery
/// response has been spooled and before the normal streaming verifier sees it.
/// Production callers use the default `.none`; acceptance runs use
/// `.corruptLastByte` to prove a bad STAR archive cannot replace the durable head.
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

/// A native Nov-12 HTTP source: independently MAC-authenticates a fresh head
/// observation and STAR metadata using a new HPKE export per request. Full
/// record/digest validation and transactional publication happen in the
/// recovery orchestrator; a metadata MAC alone is never a complete-repo proof.
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
        let query = ["repo": target.repositoryDID, "space": target.space.rawValue]
        let latestPath = try host.client.xrpcPath("com.atproto.space.getLatestCommit", query: query)
        let latest = try await PermissionedSpaceMACHTTP.query(
            host: host, nsid: "com.atproto.space.getLatestCommit", query: query,
            space: target.space, author: target.repositoryDID,
            authorization: {
                try await self.authorization(path: latestPath, provider: self.host.authorizationProvider, fallback: self.host.authorization)
            },
            commit: { try StrictJSON.decode(ComAtprotoSpaceGetLatestCommit.Output.self, from: $0).commit }
        )
        guard (200...299).contains(latest.response.status), let latestCommit = latest.commit else {
            throw InteropHTTPError.unexpectedStatus(latest.response.status)
        }
        let freshness = try PermissionedRemoteReplicaFreshnessWitness(
            wireRevision: TID(tidString: latestCommit.rev), commitment: latestCommit.data
        )
        guard let lease = spoolAdmission.reserve(accountDID: target.receiverDID, maximumBytes: limits.maximumCARBytes) else {
            throw InteropHTTPError.responseTooLarge
        }
        let spoolURL = temporaryDirectory.appending(path: "swan-permissioned-recovery-\(UUID().uuidString).star")
        do {
            let path = try host.client.xrpcPath("com.atproto.space.getRepo", query: query)
            let authenticated = try await PermissionedSpaceMACHTTP.streamSTAR(
                host: host, query: query, space: target.space, author: target.repositoryDID,
                destination: spoolURL, maximumBytes: limits.maximumCARBytes,
                authorization: {
                    try await self.authorization(path: path, provider: self.host.authorizationProvider, fallback: self.host.authorization)
                }
            )
            guard (200...299).contains(authenticated.response.status),
                  let authenticatedCommit = authenticated.commit else {
                throw InteropHTTPError.unexpectedStatus(authenticated.response.status)
            }
            let identity = try PermissionedRemoteReplicaSourceIdentity(
                origin: host.client.http.baseURL, repositoryDID: target.repositoryDID,
                verifierIdentity: authenticated.request.verifierIdentity
            )
            try fault.apply(to: spoolURL)
            let source = try PermissionedRemoteReplicaFileSource(fileURL: spoolURL)
            return try PermissionedRemoteReplicaSourceSession(
                identity: identity,
                authorKEMKey: authenticated.request.authorKEMKey,
                authenticatedCommit: authenticatedCommit,
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

}

/// Owner-only, one-shot archive source used by the HTTP provider.  Keeping the
/// descriptor behind an actor prevents a verifier and cleanup callback from
/// racing a close or accidentally reading a second time.
actor PermissionedRemoteReplicaFileSource:
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
        let bytes = try handle.read(upToCount: maximumBytes)
        return bytes?.isEmpty == true ? nil : bytes
    }

    func close() {
        guard let handle else { return }
        self.handle = nil
        try? handle.close()
    }
}
