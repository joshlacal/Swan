import Foundation
import Petrel
import SwanSpaces

/// A permissioned repository copied into another account's PDS for recovery
/// and synchronization. This type is deliberately distinct from the
/// authority-owned repository key used by `permissioned_repository_state`.
public struct PermissionedRemoteReplicaTarget: Sendable, Hashable {
    public let receiverDID: String
    public let space: SpaceURI
    public let repositoryDID: String

    public init(
        receiverDID: String,
        space: SpaceURI,
        repositoryDID: String
    ) throws {
        guard (try? DID(didString: receiverDID)) != nil,
              (try? DID(didString: repositoryDID)) != nil else {
            throw PermissionedRemoteReplicaRecoveryError.invalidBinding
        }
        self.receiverDID = receiverDID
        self.space = space
        self.repositoryDID = repositoryDID
    }
}

public struct PermissionedRemoteReplicaHead: Sendable, Equatable {
    public let target: PermissionedRemoteReplicaTarget
    public let generation: UInt64
    public let wireRevision: TID
    public let historyFloorWireRevision: TID
    public let ltHash: Data
    public let commitment: Data
    public let stateMarker: Data

    public init(
        target: PermissionedRemoteReplicaTarget,
        generation: UInt64,
        wireRevision: TID,
        historyFloorWireRevision: TID,
        ltHash: Data,
        commitment: Data,
        stateMarker: Data
    ) throws {
        guard generation > 0,
              generation <= UInt64(Int.max),
              ltHash.count == LtHash.byteCount,
              commitment.count == 32,
              !stateMarker.isEmpty,
              stateMarker.count
                <= PermissionedRemoteReplicaRecoveryBudgets
                    .maximumStateMarkerBytes else {
            throw PermissionedRemoteReplicaRecoveryError.invalidBinding
        }
        self.target = target
        self.generation = generation
        self.wireRevision = wireRevision
        self.historyFloorWireRevision = historyFloorWireRevision
        self.ltHash = ltHash
        self.commitment = commitment
        self.stateMarker = stateMarker
    }
}

/// A signed, key-resolved `getLatestCommit` (or equivalent writer-registry)
/// observation made before downloading a full CAR.
public struct PermissionedRemoteReplicaFreshnessWitness:
    Sendable, Equatable
{
    public let wireRevision: TID
    public let commitment: Data

    public init(wireRevision: TID, commitment: Data) throws {
        guard commitment.count == 32 else {
            throw PermissionedRemoteReplicaRecoveryError.invalidBinding
        }
        self.wireRevision = wireRevision
        self.commitment = commitment
    }
}

public struct PermissionedRemoteReplicaImportBinding:
    Sendable, Equatable
{
    public let requestID: String
    public let requestDigest: Data
    public let sourceOrigin: String
    public let target: PermissionedRemoteReplicaTarget
    public let expectedBase: PermissionedRemoteReplicaHead?
    public let freshnessWitness: PermissionedRemoteReplicaFreshnessWitness?
    public let verifierIdentity: String
    public let profileID: String
    public let limits: SpaceCARRecoveryLimits

    public init(
        requestID: String,
        requestDigest: Data,
        sourceOrigin: String,
        target: PermissionedRemoteReplicaTarget,
        expectedBase: PermissionedRemoteReplicaHead?,
        freshnessWitness: PermissionedRemoteReplicaFreshnessWitness?,
        verifierIdentity: String,
        profileID: String,
        limits: SpaceCARRecoveryLimits = .standard
    ) throws {
        guard !requestID.isEmpty, requestID.utf8.count <= 512,
              !requestID.contains("\0"),
              requestDigest.count == 32,
              !sourceOrigin.isEmpty, sourceOrigin.utf8.count <= 2_048,
              !sourceOrigin.contains("\0"),
              !verifierIdentity.isEmpty,
              verifierIdentity.utf8.count <= 512,
              !verifierIdentity.contains("\0"),
              !profileID.isEmpty, profileID.utf8.count <= 256,
              !profileID.contains("\0"),
              // Every remote full-CAR install, including first bootstrap, must
              // be tied to a separately authenticated current-head witness.
              // `expectedBase` is only the local CAS precondition; it is never
              // evidence that the downloaded archive is fresh.
              freshnessWitness != nil,
              expectedBase == nil || expectedBase?.target == target else {
            throw PermissionedRemoteReplicaRecoveryError.invalidBinding
        }
        self.requestID = requestID
        self.requestDigest = requestDigest
        self.sourceOrigin = sourceOrigin
        self.target = target
        self.expectedBase = expectedBase
        self.freshnessWitness = freshnessWitness
        self.verifierIdentity = verifierIdentity
        self.profileID = profileID
        self.limits = limits
    }
}

public enum PermissionedRemoteReplicaImportStatus:
    String, Sendable, Equatable, Hashable
{
    case receiving
    case verifying
    case verified
    case preparing
    case poisoned
    case consumed
}

/// Fixed process-independent ceilings for the durable recovery machinery.
/// Wire-size limits remain request/profile-bound; these budgets bound each
/// individual SQLite result and write transaction.
public struct PermissionedRemoteReplicaRecoveryBudgets:
    Sendable, Equatable
{
    public static let maximumRowsPerPass = 128
    public static let maximumChunksPerRecord = 16
    public static let maximumChunkBytes =
        SpaceCARRecoveryLimits.maximumChunkBytes
    public static let maximumCommitBytes =
        SpaceCARRecoveryLimits.absoluteMaximumCommitBytes
    public static let maximumStateMarkerBytes = 64 * 1_024

    public init() {}
}

public struct PermissionedRemoteReplicaImportSession:
    Sendable, Equatable
{
    public let id: String
    public let binding: PermissionedRemoteReplicaImportBinding
    public let createdAt: Int64
    public let expiresAt: Int64
    public let status: PermissionedRemoteReplicaImportStatus

    public init(
        id: String,
        binding: PermissionedRemoteReplicaImportBinding,
        createdAt: Int64,
        expiresAt: Int64,
        status: PermissionedRemoteReplicaImportStatus
    ) {
        self.id = id
        self.binding = binding
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.status = status
    }
}

public struct CommittedPermissionedRemoteReplicaRecovery:
    Sendable, Equatable
{
    public let requestID: String
    public let requestDigest: Data
    public let verifierIdentity: String
    public let head: PermissionedRemoteReplicaHead
    public let commitRootCID: String
    public let indexRootCID: String
    public let recordCount: Int
    public let uniqueBlockCount: Int
    public let committedAt: Int64

    public init(
        requestID: String,
        requestDigest: Data,
        verifierIdentity: String,
        head: PermissionedRemoteReplicaHead,
        commitRootCID: String,
        indexRootCID: String,
        recordCount: Int,
        uniqueBlockCount: Int,
        committedAt: Int64
    ) {
        self.requestID = requestID
        self.requestDigest = requestDigest
        self.verifierIdentity = verifierIdentity
        self.head = head
        self.commitRootCID = commitRootCID
        self.indexRootCID = indexRootCID
        self.recordCount = recordCount
        self.uniqueBlockCount = uniqueBlockCount
        self.committedAt = committedAt
    }
}

public enum PermissionedRemoteReplicaImportStartOutcome:
    Sendable, Equatable
{
    case staged(PermissionedRemoteReplicaImportSession)
    case committed(CommittedPermissionedRemoteReplicaRecovery)
}

public enum PermissionedRemoteReplicaRecoveryError:
    Error, Sendable, Equatable
{
    case invalidBinding
    case invalidTimestamp
    case receiverMismatch
    case unknownSession
    case expiredSession
    case importInProgress
    case poisonedSession
    case conflictingRequestReuse
    case bindingMismatch
    case verificationRequired
    case invalidStatus
    case duplicateIndexEntry
    case duplicateBlockConflict
    case invalidChunk
    case incompleteBlock
    case corruptStaging
    case corruptReplica
    case targetCASConflict
    case staleRecovery
    case equivocation
    case freshnessMismatch
}

/// Network-free durable boundary for one receiver account's permissioned
/// remote replicas. Verification can perform key lookup before calling
/// `mark...Verified`; publication reloads only immutable staged facts.
public protocol PermissionedRemoteReplicaRecoveryStore: Sendable {
    func permissionedRemoteReplicaHead(
        target: PermissionedRemoteReplicaTarget
    ) async throws -> PermissionedRemoteReplicaHead?

    func createPermissionedRemoteReplicaImportSession(
        binding: PermissionedRemoteReplicaImportBinding,
        createdAt: Int64,
        expiresAt: Int64,
        now: Int64
    ) async throws -> PermissionedRemoteReplicaImportStartOutcome

    func permissionedRemoteReplicaImportSession(
        id: String
    ) async throws -> PermissionedRemoteReplicaImportSession

    func stagePermissionedRemoteReplicaRoots(
        sessionID: String,
        commit: CID,
        index: CID,
        now: Int64
    ) async throws

    func stagePermissionedRemoteReplicaCommit(
        sessionID: String,
        cid: CID,
        body: Data,
        now: Int64
    ) async throws

    func stagePermissionedRemoteReplicaIndexEntry(
        sessionID: String,
        entry: SpaceCARRecoveryIndexEntry,
        now: Int64
    ) async throws

    func nextUnconsumedPermissionedRemoteReplicaIndexEntry(
        sessionID: String,
        now: Int64
    ) async throws -> SpaceCARRecoveryIndexEntry?

    func consumePermissionedRemoteReplicaIndexEntries(
        sessionID: String,
        cid: CID,
        now: Int64
    ) async throws -> Int

    func beginPermissionedRemoteReplicaRecord(
        sessionID: String,
        cid: CID,
        byteCount: Int,
        now: Int64
    ) async throws

    func appendPermissionedRemoteReplicaRecordChunk(
        sessionID: String,
        cid: CID,
        chunkIndex: Int,
        bytes: Data,
        now: Int64
    ) async throws

    func completePermissionedRemoteReplicaRecord(
        sessionID: String,
        cid: CID,
        byteCount: Int,
        chunkCount: Int,
        now: Int64
    ) async throws

    func markPermissionedRemoteReplicaImportVerified(
        sessionID: String,
        verification: VerifiedStreamingSpaceCARRecovery,
        now: Int64
    ) async throws

    func publishVerifiedPermissionedRemoteReplicaRecovery(
        sessionID: String,
        consumedAt: Int64,
        now: Int64
    ) async throws -> CommittedPermissionedRemoteReplicaRecovery

    func poisonPermissionedRemoteReplicaImportSession(id: String) async
    func cleanupPermissionedRemoteReplicaImportSession(id: String) async throws
    func recoverExpiredPermissionedRemoteReplicaImportSessions(
        now: Int64
    ) async throws -> Int
}
