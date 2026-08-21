import Crypto
import Foundation
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanSpacesWire
import SwanStorage

public enum PermissionedRemoteReplicaIncrementalSyncOutcome:
    Sendable, Equatable
{
    case applied(AppliedPermissionedRemoteReplicaIncrementalBatch)
    case exactDuplicate(AppliedPermissionedRemoteReplicaIncrementalBatch)
    case unchanged(PermissionedRemoteReplicaHead)
    case fullCARRecoveryRequired
    case casConflict
    case conflictingReplay
    case staleOrReordered
    case integrityFailure
}

/// Fetches one bounded value-bearing incremental interval, authenticates its
/// terminal reader-specific commit against a fresh `getLatestCommit`, and only
/// then hands the complete batch to the network-free durable store.
public struct PermissionedRemoteReplicaIncrementalHTTPOrchestrator: Sendable {
    private static let maximumWirePageOperations = 1_000
    public typealias PublicationAuthorization = @Sendable (
        @escaping @Sendable () async throws
            -> PermissionedRemoteReplicaIncrementalApplyOutcome
    ) async throws -> PermissionedRemoteReplicaIncrementalApplyOutcome

    public let source: LiveInteropHost
    public let store: any PermissionedRemoteReplicaIncrementalStore
    private let publicationAuthorization: PublicationAuthorization

    public init(
        source: LiveInteropHost,
        store: any PermissionedRemoteReplicaIncrementalStore,
        publicationAuthorization: @escaping PublicationAuthorization = {
            operation in try await operation()
        }
    ) {
        self.source = source
        self.store = store
        self.publicationAuthorization = publicationAuthorization
    }

    public func synchronize(
        target: PermissionedRemoteReplicaTarget,
        requestID: String,
        requestSequence: UInt64,
        appliedAt: Int64
    ) async throws -> PermissionedRemoteReplicaIncrementalSyncOutcome {
        Self.stageLog("synchronize start for \(target.repositoryDID)")
        guard let key = source.permissionedCommitVerificationKey else {
            throw InteropHTTPError.transportFailure
        }
        guard let base = try await store
            .permissionedRemoteReplicaIncrementalBaseState(target: target) else {
            return .fullCARRecoveryRequired
        }
        Self.stageLog("incremental base state loaded")

        let page = try await listRepoOps(
            target: target,
            since: base.head.wireRevision.toString()
        )
        Self.stageLog("listRepoOps response received")
        let output: ComAtprotoSpaceListRepoOps.Output
        switch page {
        case .fullRecoveryRequired:
            return .fullCARRecoveryRequired
        case let .output(value):
            output = value
        }
        guard output.cursor == nil else {
            throw PermissionedRemoteReplicaIncrementalVerificationError
                .invalidOperation
        }
        guard let terminalCommit = output.commit else {
            // The pinned handler omits the commit only when exactly `limit`
            // operations were returned. Its continuation key is only `rev`,
            // while every operation in one atomic applyWrites batch shares a
            // revision. Advancing `since` can therefore skip the remainder of
            // a revision split by the wire limit. Select full CAR instead of
            // attempting a lossy revision-only continuation.
            if output.ops.count == Self.maximumWirePageOperations {
                return .fullCARRecoveryRequired
            }
            throw PermissionedRemoteReplicaIncrementalVerificationError
                .invalidCommit
        }
        let operations = output.ops
        // The pinned PDS omits values for mutations superseded by a later
        // operation in the requested interval. The durable store cannot
        // materialize those intermediate CIDs without their authenticated
        // bytes, so recover the complete current repository instead of
        // surfacing a non-retryable verifier failure. Deletes have no value by
        // definition and remain valid incremental operations.
        if operations.contains(where: {
            $0.cid != nil && $0.value == nil
        }) {
            return .fullCARRecoveryRequired
        }

            let latest = try await getLatestCommit(
                target: target,
                verificationKey: key
            )
            Self.stageLog("getLatestCommit verified")

            if operations.isEmpty {
                let page = try PermissionedRemoteReplicaIncrementalVerifier
                    .verifyCommit(
                        terminalCommit,
                        target: target,
                        verificationKey: key
                    )
                try PermissionedRemoteReplicaIncrementalVerifier.requireSameHead(
                    page, latest
                )
                guard page.wireRevision == base.head.wireRevision,
                      page.commitment == base.head.commitment else {
                    throw PermissionedRemoteReplicaIncrementalVerificationError
                        .mixedHead
                }
                return .unchanged(base.head)
            }

            let verified = try PermissionedRemoteReplicaIncrementalVerifier
                .verify(
                    operations: operations,
                    commit: terminalCommit,
                    base: base,
                    target: target,
                    verificationKey: key
                )
            Self.stageLog("incremental interval verified (\(verified.operations.count) operations)")
            try PermissionedRemoteReplicaIncrementalVerifier.requireSameHead(
                verified.freshnessWitness, latest
            )
            let digest = PermissionedRemoteReplicaIncrementalBatch
                .canonicalDigest(
                    target: target,
                    expectedHead: base.head,
                    terminalHead: verified.terminalHead,
                    operations: verified.operations,
                    requestSequence: requestSequence
                )
            let batch = try PermissionedRemoteReplicaIncrementalBatch(
                target: target,
                expectedHead: base.head,
                terminalHead: verified.terminalHead,
                operations: verified.operations,
                requestID: requestID,
                requestSequence: requestSequence,
                requestDigest: digest
            )
            return map(try await publicationAuthorization {
                Self.stageLog("durable apply starting")
                let outcome = try await store.applyVerifiedPermissionedRemoteReplicaBatch(
                    batch,
                    appliedAt: appliedAt
                )
                Self.stageLog("durable apply completed")
                return outcome
            })
    }

    private enum ListResult {
        case output(ComAtprotoSpaceListRepoOps.Output)
        case fullRecoveryRequired
    }

    private struct ErrorBody: Decodable {
        let error: String
    }

    private func listRepoOps(
        target: PermissionedRemoteReplicaTarget,
        since: String
    ) async throws -> ListResult {
        let query = [
            "space": target.space.rawValue,
            "repo": target.repositoryDID,
            "since": since,
            "limit": String(Self.maximumWirePageOperations),
        ]
        let path = try source.client.xrpcPath(
            "com.atproto.space.listRepoOps", query: query
        )
        let response: InteropHTTPResponse
        do {
            response = try await source.client.query(
                "com.atproto.space.listRepoOps",
                query: query,
                authorization: try await authorization(path: path)
            )
        } catch InteropHTTPError.responseTooLarge {
            // A legitimate value-bearing page can exceed the bounded JSON
            // client's memory ceiling even though its operation count is at
            // the pinned wire limit. The complete repository CAR is already
            // the safe recovery representation for an unconsumable interval.
            return .fullRecoveryRequired
        }
        if response.status == 409 {
            guard response.header("content-type")?.lowercased().contains("json")
                    == true,
                  let error = try? StrictJSON.decode(
                      ErrorBody.self,
                      from: response.body
                  ),
                  error.error == "full_repo_recovery_required" else {
                throw InteropHTTPError.unexpectedStatus(response.status)
            }
            return .fullRecoveryRequired
        }
        guard (200 ... 299).contains(response.status),
              response.header("content-type")?.lowercased().contains("json")
                == true else {
            throw InteropHTTPError.unexpectedStatus(response.status)
        }
        return .output(try StrictJSON.decode(
            ComAtprotoSpaceListRepoOps.Output.self,
            from: response.body
        ))
    }

    private func getLatestCommit(
        target: PermissionedRemoteReplicaTarget,
        verificationKey: PermissionedDataJWTVerificationKey
    ) async throws -> PermissionedRemoteReplicaFreshnessWitness {
        let query = [
            "space": target.space.rawValue,
            "repo": target.repositoryDID,
        ]
        let path = try source.client.xrpcPath(
            "com.atproto.space.getLatestCommit", query: query
        )
        let response = try await source.client.query(
            "com.atproto.space.getLatestCommit",
            query: query,
            authorization: try await authorization(path: path)
        )
        guard (200 ... 299).contains(response.status),
              response.header("content-type")?.lowercased().contains("json")
                == true else {
            throw InteropHTTPError.unexpectedStatus(response.status)
        }
        let output = try StrictJSON.decode(
            ComAtprotoSpaceGetLatestCommit.Output.self,
            from: response.body
        )
        let commit = output.commit
        return try PermissionedRemoteReplicaIncrementalVerifier.verifyCommit(
            commit,
            target: target,
            verificationKey: verificationKey
        )
    }

    private func authorization(path: String) async throws -> InteropAuthorization {
        guard let provider = source.authorizationProvider,
              let target = URL(
                string: path,
                relativeTo: source.client.http.baseURL
              )?.absoluteURL else {
            return source.authorization
        }
        return try await provider(.get, target, nil)
    }

    private func map(
        _ outcome: PermissionedRemoteReplicaIncrementalApplyOutcome
    ) -> PermissionedRemoteReplicaIncrementalSyncOutcome {
        switch outcome {
        case let .applied(result): .applied(result)
        case let .exactDuplicate(result): .exactDuplicate(result)
        case .casConflict: .casConflict
        case .conflictingReplay: .conflictingReplay
        case .staleOrReordered: .staleOrReordered
        case .integrityFailure: .integrityFailure
        case .fullCARRecoveryRequired: .fullCARRecoveryRequired
        }
    }

    /// Emits one bounded stage marker on stderr when the operator enables
    /// `SWAN_SYNC_STAGE_LOG=1`. The stateful matrix and `lab live` keep this
    /// off by default so their sanitized output shape never changes.
    private static func stageLog(_ message: String) {
        guard ProcessInfo.processInfo.environment["SWAN_SYNC_STAGE_LOG"] == "1" else {
            return
        }
        FileHandle.standardError.write(Data(("[sync] \(message)\n").utf8))
    }
}
