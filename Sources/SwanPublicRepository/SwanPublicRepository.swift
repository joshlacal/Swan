import Foundation
import Petrel
import SwanCore

/// The alpha deliberately exposes a small public-repository substrate: valid
/// identity state, public repository status, and export. Public record writes,
/// relays, and firehose behavior are intentionally not implied by this type.
public struct EmptyPublicRepository: Sendable, Equatable {
    public let did: String
    public let revision: String

    public init(did: String, revision: String = "0") throws {
        guard did.hasPrefix("did:") else { throw SwanError.invalidIdentifier(did) }
        self.did = did
        self.revision = revision
    }
}

/// Retains an explicit compile-time dependency on Petrel's canonical CID/CAR
/// implementation; public CAR construction is added only after its conformance
/// vectors and generated server contracts land.
public typealias PetrelCID = CID
