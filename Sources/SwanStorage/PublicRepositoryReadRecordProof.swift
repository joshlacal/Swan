import Foundation
import Petrel
import PetrelRepo

/// Hard bound for the anonymous `com.atproto.sync.getRecord` response.
///
/// A record proof is the signed commit, the MST nodes on one root-to-key
/// search path, and at most one record block, so it is small by construction:
/// a well-formed tree is at most 129 layers deep and a record block is at most
/// `PublicRepositoryLimits.standard.maximumRecordBlockBytes`. The ceiling is
/// the same one `com.atproto.repo.getRecord` reserves, so both single-record
/// reads draw one lease class from the shared JSON read admission and neither
/// can hold more of it than the other. A proof that would exceed it is refused
/// before it is materialized rather than spooled to disk: the multi-gigabyte
/// CAR spool path belongs to `getRepo` alone.
public enum PublicRepositoryRecordProofLimits {
    public static let maximumProofCARBytes =
        PublicRepositoryJSONReadLimits.maximumGetRecordResponseBytes
}

/// One `com.atproto.sync.getRecord` proof, already encoded.
///
/// `car` is a CARv1 archive whose single root is the signed commit and whose
/// blocks are that commit, the MST nodes on the search path for the requested
/// key, and the record block when the key is present. `recordCID` is `nil`
/// when the same path proves the key absent — that is still a successful
/// read, exactly as it is on the reference PDS.
///
/// The shape carries bytes this server already publishes through `getRepo`
/// and nothing else: no credentials, keys, or permissioned repository data.
public struct PublicRepositoryReadRecordProof: Sendable, Equatable {
    public let did: String
    public let state: PublicRepositoryState
    public let recordCID: CID?
    public let car: Data

    public init(
        did: String,
        state: PublicRepositoryState,
        recordCID: CID?,
        car: Data
    ) throws {
        guard AccountControlIdentifiers.isDID(did),
              state.did == did,
              !car.isEmpty else {
            throw PublicRepositoryReadError.unavailable(
                reason: .malformedProjectionValue
            )
        }
        guard car.count <= PublicRepositoryRecordProofLimits
            .maximumProofCARBytes else {
            throw PublicRepositoryReadError.resourceLimitExceeded
        }
        self.did = did
        self.state = state
        self.recordCID = recordCID
        self.car = car
    }
}
