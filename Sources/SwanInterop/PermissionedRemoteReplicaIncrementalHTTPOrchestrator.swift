import Foundation
import Petrel
import SwanAccounts
import SwanCore
import SwanOAuth
import SwanSpaces
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

/// Fetches bounded value-bearing pages, authenticates each page's required
/// reader-specific commit, and only then hands the complete batch to the
/// network-free durable store.
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
        let operations: [ComAtprotoSpaceListRepoOps.OpEntry]
        let terminalCommit: ComAtprotoSpaceDefs.Commit
        let authenticatedCommit: SpaceRepositoryCommit
        switch page {
        case .fullRecoveryRequired:
            return .fullCARRecoveryRequired
        case let .output(value):
            operations = value.operations
            terminalCommit = value.commit
            authenticatedCommit = value.authenticatedCommit
        }
        // Every page has already authenticated the host's current commit with
        // a fresh HPKE export. Only the final page's commit is compared with
        // the state after all pages have been applied.
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
            target: target
        )
        Self.stageLog("getLatestCommit verified")

        if operations.isEmpty {
            let page = try PermissionedRemoteReplicaIncrementalVerifier
                .verifyCommit(
                    terminalCommit,
                    target: target,
                    authenticatedCommit: authenticatedCommit
                )
            try PermissionedRemoteReplicaIncrementalVerifier.requireSameHead(
                page, latest
            )
            if page.wireRevision == base.head.wireRevision,
               page.commitment == base.head.commitment {
                return .unchanged(base.head)
            }
            // An authenticated, newer head with no oplog entries after the
            // checkpoint is a legitimate reference state: `clearRecords`
            // truncates the oplog and changes the data digest, and
            // `importRepo` truncates it and advances the rev over unchanged
            // data. Neither is expressible as an incremental batch (the
            // durable store requires operations), so recover the complete
            // repository. A head that is not newer than the checkpoint is a
            // stale or rolled-back answer and is never accepted.
            guard page.wireRevision > base.head.wireRevision else {
                throw PermissionedRemoteReplicaIncrementalVerificationError
                    .mixedHead
            }
            return .fullCARRecoveryRequired
        }

        let verified: VerifiedPermissionedRemoteReplicaIncrementalPage
        do {
            verified = try PermissionedRemoteReplicaIncrementalVerifier
                .verify(
                    operations: operations,
                    commit: terminalCommit,
                    base: base,
                    target: target,
                    authenticatedCommit: authenticatedCommit
                )
        } catch PermissionedRemoteReplicaIncrementalVerificationError
            .commitmentMismatch {
            // Writes after a `clearRecords` (or an import) reach the oplog,
            // but the truncated history no longer carries the deletes that
            // bridge the checkpoint to the new digest, so the replayed LtHash
            // cannot match. Only an authenticated, current and newer terminal
            // head may select recovery; an unauthenticated page must not be
            // able to force it.
            let terminal = try PermissionedRemoteReplicaIncrementalVerifier
                .verifyCommit(
                    terminalCommit,
                    target: target,
                    authenticatedCommit: authenticatedCommit
                )
            try PermissionedRemoteReplicaIncrementalVerifier.requireSameHead(
                terminal, latest
            )
            guard terminal.wireRevision > base.head.wireRevision else {
                throw PermissionedRemoteReplicaIncrementalVerificationError
                    .commitmentMismatch
            }
            return .fullCARRecoveryRequired
        }
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
        let batch: PermissionedRemoteReplicaIncrementalBatch
        do {
            batch = try PermissionedRemoteReplicaIncrementalBatch(
                target: target,
                expectedHead: base.head,
                terminalHead: verified.terminalHead,
                operations: verified.operations,
                requestID: requestID,
                requestSequence: requestSequence,
                requestDigest: digest
            )
        } catch PermissionedRemoteReplicaIncrementalInputError.invalidOperationBudget {
            // The authenticated interval can fit the HTTP cap while exceeding
            // the durable batch's aggregate value budget. Recover via bounded
            // STAR staging without partially applying this interval.
            return .fullCARRecoveryRequired
        }
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

    private static func validContinuation(_ cursor: String, lastRevision: String) -> Bool {
        let pieces = cursor.split(separator: "/", omittingEmptySubsequences: false)
        guard pieces.count == 2, pieces[0] == lastRevision,
              let index = UInt64(pieces[1]), index <= 9_007_199_254_740_991,
              String(index) == pieces[1] else { return false }
        return true
    }

    private struct ListedOperations {
        let operations: [ComAtprotoSpaceListRepoOps.OpEntry]
        let commit: ComAtprotoSpaceDefs.Commit
        let authenticatedCommit: SpaceRepositoryCommit
    }

    private enum ListResult {
        case output(ListedOperations)
        case fullRecoveryRequired
    }

    private struct ErrorBody: Decodable {
        let error: String
    }

    private func listRepoOps(
        target: PermissionedRemoteReplicaTarget,
        since: String
    ) async throws -> ListResult {
        var cursor: String?
        var seenCursors = Set<String>()
        var operations: [ComAtprotoSpaceListRepoOps.OpEntry] = []
        while true {
            var query = [
                "space": target.space.rawValue,
                "repo": target.repositoryDID,
                "since": since,
                "limit": String(Self.maximumWirePageOperations),
            ]
            query["cursor"] = cursor
            let path = try source.client.xrpcPath(
                "com.atproto.space.listRepoOps",
                query: query
            )
            let authenticated: PermissionedSpaceMACResponse
            do {
                authenticated = try await PermissionedSpaceMACHTTP.query(
                    host: source,
                    nsid: "com.atproto.space.listRepoOps",
                    query: query,
                    space: target.space,
                    author: target.repositoryDID,
                    authorization: { try await self.authorization(path: path) },
                    commit: {
                        try StrictJSON.decode(
                            ComAtprotoSpaceListRepoOps.Output.self,
                            from: $0
                        ).commit
                    }
                )
            } catch InteropHTTPError.responseTooLarge {
                return .fullRecoveryRequired
            }
            let response = authenticated.response
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
            let output = try StrictJSON.decode(
                ComAtprotoSpaceListRepoOps.Output.self,
                from: response.body
            )
            let commit = output.commit
            guard let authenticatedCommit = authenticated.commit else {
                throw PermissionedRemoteReplicaIncrementalVerificationError.invalidCommit
            }
            guard output.ops.count <= Self.maximumWirePageOperations else {
                return .fullRecoveryRequired
            }
            guard output.ops.count <= SpaceWriteLimits.maximumOperations - operations.count else {
                return .fullRecoveryRequired
            }
            operations.append(contentsOf: output.ops)
            guard let next = output.cursor else {
                return .output(.init(
                    operations: operations,
                    commit: commit,
                    authenticatedCommit: authenticatedCommit
                ))
            }
            guard let last = output.ops.last,
                  Self.validContinuation(next, lastRevision: last.rev.toString()),
                  seenCursors.insert(next).inserted else {
                throw PermissionedRemoteReplicaIncrementalVerificationError.invalidOperation
            }
            cursor = next
        }
    }

    private func getLatestCommit(
        target: PermissionedRemoteReplicaTarget
    ) async throws -> PermissionedRemoteReplicaFreshnessWitness {
        let query = ["space": target.space.rawValue, "repo": target.repositoryDID]
        let path = try source.client.xrpcPath("com.atproto.space.getLatestCommit", query: query)
        let authenticated = try await PermissionedSpaceMACHTTP.query(
            host: source, nsid: "com.atproto.space.getLatestCommit", query: query,
            space: target.space, author: target.repositoryDID,
            authorization: { try await self.authorization(path: path) },
            commit: { try StrictJSON.decode(ComAtprotoSpaceGetLatestCommit.Output.self, from: $0).commit }
        )
        guard (200...299).contains(authenticated.response.status), let commit = authenticated.commit else {
            throw InteropHTTPError.unexpectedStatus(authenticated.response.status)
        }
        return try PermissionedRemoteReplicaFreshnessWitness(wireRevision: TID(tidString: commit.rev), commitment: commit.data)
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
