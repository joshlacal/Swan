import Foundation
import Petrel
import PetrelRepo

public enum PublicRepositoryMutationStoreError: Error, Sendable, Equatable {
    case invalidRequest
    case invalidRequestDigest
    case conflictingRequestReuse
    case repositoryNotInstalled
    case ownershipMismatch
    case commitCASConflict
    case reservationMismatch
    case preparedMutationMismatch
    case publicBlobNotReachable
    case revisionExhausted
    case corruptRepository
    case blockQuotaExceeded
}

public struct PublicRepositoryBlockQuota: Sendable, Equatable {
    public let maximumTotalBytes: Int
    public let maximumTotalBlocks: Int

    public static let standard = PublicRepositoryBlockQuota(
        maximumTotalBytes: PublicRepositoryLimits.standard.maximumCARBytes * 2,
        maximumTotalBlocks: PublicRepositoryLimits.standard.maximumCARBlocks * 2
    )

    public init(maximumTotalBytes: Int, maximumTotalBlocks: Int) {
        self.maximumTotalBytes = maximumTotalBytes
        self.maximumTotalBlocks = maximumTotalBlocks
    }
}

/// Retryable failure from the final control-plane publication fence. This is
/// separate from durable mutation-store failures so adding a fence outcome
/// does not alter repository persistence error exhaustiveness.
public enum PublicRepositoryMutationPublicationError: Error, Sendable, Equatable {
    case staleSigningGeneration
}

public struct PublicRepositoryMutationRequest: Sendable, Equatable {
    public let id: String
    public let canonicalDigest: Data
    public let baseCommitCID: CID

    public init(id: String, canonicalDigest: Data, baseCommitCID: CID) throws {
        guard !id.isEmpty, id.utf8.count <= 512, !id.contains("\0") else {
            throw PublicRepositoryMutationStoreError.invalidRequest
        }
        guard canonicalDigest.count == 32 else {
            throw PublicRepositoryMutationStoreError.invalidRequestDigest
        }
        do {
            try PublicRepositoryCID.validate(baseCommitCID)
        } catch {
            throw PublicRepositoryMutationStoreError.invalidRequest
        }
        self.id = id
        self.canonicalDigest = canonicalDigest
        self.baseCommitCID = baseCommitCID
    }
}

public struct PublicRepositoryMutationReservation: Sendable, Equatable {
    public let request: PublicRepositoryMutationRequest
    public let repositoryDID: String
    public let baseRevision: String
    public let nextRevision: String

    public init(
        request: PublicRepositoryMutationRequest,
        repositoryDID: String,
        baseRevision: String,
        nextRevision: String
    ) throws {
        guard (try? DID(didString: repositoryDID)) != nil else {
            throw PublicRepositoryMutationStoreError.ownershipMismatch
        }
        _ = try PublicRepositoryTID(baseRevision)
        _ = try PublicRepositoryTID(nextRevision)
        self.request = request
        self.repositoryDID = repositoryDID
        self.baseRevision = baseRevision
        self.nextRevision = nextRevision
    }
}

public struct CommittedPublicRepositoryMutation: Sendable, Equatable {
    public let state: PublicRepositoryState
    public let recordResults: [PublicRepositoryMutationRecordResult]

    public init(
        state: PublicRepositoryState,
        recordResults: [PublicRepositoryMutationRecordResult]
    ) {
        self.state = state
        self.recordResults = recordResults
    }
}

public enum PublicRepositoryMutationReservationOutcome: Sendable, Equatable {
    case reserved(PublicRepositoryMutationReservation)
    case committed(CommittedPublicRepositoryMutation)
}

/// One account database's public-repository truth. Revision preparation and
/// signing deliberately occur between `reserve` and `apply`, outside storage.
public protocol PublicRepositoryMutationStore: PublicRepositoryBlockSource {
    func loadPublicRepositoryState() async throws -> PublicRepositoryState?
    func verifyPublicRepositoryProjection() async throws
    func publicRepositoryRecordCID(for path: PublicRepositoryPath) async throws -> CID?
    func reservePublicRepositoryRevision(
        _ request: PublicRepositoryMutationRequest,
        wallClockMicroseconds: UInt64
    ) async throws -> PublicRepositoryMutationReservationOutcome
    func applyPublicRepositoryMutation(
        reservation: PublicRepositoryMutationReservation,
        prepared: PreparedPublicRepositoryMutation
    ) async throws -> CommittedPublicRepositoryMutation
    func abandonPublicRepositoryReservation(
        _ reservation: PublicRepositoryMutationReservation
    ) async throws
}
