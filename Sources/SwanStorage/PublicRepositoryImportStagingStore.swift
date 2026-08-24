import Foundation
import Petrel
import PetrelRepo

public enum PublicRepositoryImportStagingError: Error, Sendable, Equatable {
    case invalidBinding
    case invalidTimestamp
    case unknownSession
    case expiredSession
    case consumedSession
    case importInProgress
    case poisonedSession
    case bindingMismatch
    case conflictingRequestReuse
    case duplicateBlockConflict
    case headerConflict
    case verificationRequired
    case repositoryNotInstalled
    case commitCASConflict
    case importedCommitMismatch
    case corruptStaging
    case corruptRepository
}

public struct PublicRepositoryImportPolicy: Sendable, Equatable {
    public let maximumRecordBlockBytes: Int
    public let maximumCARBytes: Int
    public let maximumCARBlocks: Int
    public let maximumMSTNodes: Int
    public let maximumMSTEntriesPerNode: Int
    public let maximumCBORNestingDepth: Int

    public init(limits: PublicRepositoryLimits) {
        maximumRecordBlockBytes = limits.maximumRecordBlockBytes
        maximumCARBytes = limits.maximumCARBytes
        maximumCARBlocks = limits.maximumCARBlocks
        maximumMSTNodes = limits.maximumMSTNodes
        maximumMSTEntriesPerNode = limits.maximumMSTEntriesPerNode
        maximumCBORNestingDepth = limits.maximumCBORNestingDepth
    }

    public var limits: PublicRepositoryLimits {
        get throws {
            try PublicRepositoryLimits(
                maximumRecordBlockBytes: maximumRecordBlockBytes,
                maximumCARBytes: maximumCARBytes,
                maximumCARBlocks: maximumCARBlocks,
                maximumMSTNodes: maximumMSTNodes,
                maximumMSTEntriesPerNode: maximumMSTEntriesPerNode,
                maximumCBORNestingDepth: maximumCBORNestingDepth
            )
        }
    }
}

public struct PublicRepositoryImportBinding: Sendable, Equatable {
    public let requestID: String
    public let requestDigest: Data
    public let accountDID: String
    public let expectedBaseCommitCID: CID
    public let verifierIdentity: String
    public let policy: PublicRepositoryImportPolicy

    public init(
        requestID: String,
        requestDigest: Data,
        accountDID: String,
        expectedBaseCommitCID: CID,
        verifierIdentity: String,
        policy: PublicRepositoryImportPolicy
    ) throws {
        guard !requestID.isEmpty, requestID.utf8.count <= 512,
              !requestID.contains("\0"), requestDigest.count == 32,
              (try? DID(didString: accountDID)) != nil,
              !verifierIdentity.isEmpty, verifierIdentity.utf8.count <= 512,
              !verifierIdentity.contains("\0") else {
            throw PublicRepositoryImportStagingError.invalidBinding
        }
        do {
            try PublicRepositoryCID.validate(expectedBaseCommitCID)
            _ = try policy.limits
        } catch {
            throw PublicRepositoryImportStagingError.invalidBinding
        }
        self.requestID = requestID
        self.requestDigest = requestDigest
        self.accountDID = accountDID
        self.expectedBaseCommitCID = expectedBaseCommitCID
        self.verifierIdentity = verifierIdentity
        self.policy = policy
    }
}

public enum PublicRepositoryImportStagingStatus: String, Sendable, Equatable {
    case receiving
    case verifying
    case verified
    case poisoned
    case consumed
}

public struct PublicRepositoryImportStagingSession: Sendable, Equatable {
    public let id: String
    public let binding: PublicRepositoryImportBinding
    public let createdAt: Int64
    public let expiresAt: Int64
    public let status: PublicRepositoryImportStagingStatus
    public let rootCID: CID?
    public let receivedByteCount: Int
    public let frameCount: Int

    public init(
        id: String,
        binding: PublicRepositoryImportBinding,
        createdAt: Int64,
        expiresAt: Int64,
        status: PublicRepositoryImportStagingStatus,
        rootCID: CID?,
        receivedByteCount: Int,
        frameCount: Int
    ) {
        self.id = id
        self.binding = binding
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.status = status
        self.rootCID = rootCID
        self.receivedByteCount = receivedByteCount
        self.frameCount = frameCount
    }
}

public struct CommittedPublicRepositoryImport: Sendable, Equatable {
    public let requestID: String
    public let requestDigest: Data
    public let verifierIdentity: String
    public let state: PublicRepositoryState
    public let reachableBlockCount: Int
    public let recordCount: Int

    public init(
        requestID: String,
        requestDigest: Data,
        verifierIdentity: String,
        state: PublicRepositoryState,
        reachableBlockCount: Int,
        recordCount: Int
    ) {
        self.requestID = requestID
        self.requestDigest = requestDigest
        self.verifierIdentity = verifierIdentity
        self.state = state
        self.reachableBlockCount = reachableBlockCount
        self.recordCount = recordCount
    }
}

public enum PublicRepositoryImportStartOutcome: Sendable, Equatable {
    case staged(PublicRepositoryImportStagingSession)
    case committed(CommittedPublicRepositoryImport)
}

/// Durable domain boundary for one account's CAR import staging. Implementors
/// must keep each method network- and key-lookup-free.
public protocol PublicRepositoryImportStagingStore: Sendable {
    func createPublicRepositoryImportSession(
        binding: PublicRepositoryImportBinding,
        createdAt: Int64,
        expiresAt: Int64,
        now: Int64
    ) async throws -> PublicRepositoryImportStartOutcome
    func publicRepositoryImportSession(id: String) async throws
        -> PublicRepositoryImportStagingSession
    func poisonPublicRepositoryImportSession(id: String) async
    func cleanupPublicRepositoryImportSession(id: String) async throws
    func recoverExpiredPublicRepositoryImportSessions(now: Int64) async throws -> Int
}
