import Foundation
import Petrel
import SwanOAuth
import SwanPublicRepository
import SwanStorage

/// Startup-preopened projection used by public repository mutations. The
/// request path may select only entries already present in this inventory;
/// implementations must not resolve DIDs, handles, PLC, or PDS origins over
/// the network.
public protocol PublicRepositoryMutationDirectory: Sendable {
    func publicRepositoryMutationTarget(selector: String) async throws
        -> PublicRepositoryMutationTarget?
}

public struct PublicRepositoryMutationTarget: Sendable {
    public let did: String
    public let status: AccountControlStatus
    public let store: any PublicRepositoryMutationStore

    public init(
        did: String,
        status: AccountControlStatus,
        store: any PublicRepositoryMutationStore
    ) throws {
        guard (try? DID(didString: did)) != nil else {
            throw PublicRepositoryMutationCapabilityError.invalidTarget
        }
        self.did = did
        self.status = status
        self.store = store
    }
}

/// Loads a fresh, DID-bound signing capability for each real commit. A
/// provider owns private-key handling; HTTP and repository layers never see
/// scalar bytes.
public protocol PublicRepositoryMutationSignerProvider: Sendable {
    func signer(for did: String) async throws -> any PublicRepositoryCommitSigner
}

public enum PublicRepositoryMutationCapabilityError: Error, Sendable, Equatable {
    case invalidTarget
    case unavailable
}

/// Explicit opt-in capability for public repository writes. Merely providing
/// a public read directory never enables this capability.
public struct SwanPublicRepositoryMutationCapability: Sendable {
    let authorizer: SwanOAuthResourceAuthorizer
    let directory: any PublicRepositoryMutationDirectory
    let signerProvider: any PublicRepositoryMutationSignerProvider
    let tidAllocator = SwanPermissionedTIDAllocator()
    let blobStore: (any BlobStore)?
    /// Shared with public CAR reads. Uploads reserve their worst-case spool
    /// size before `putStreaming` creates an anonymous descriptor, so a
    /// mutation capability cannot bypass the directory's disk budget.
    let publicBlobSpoolAdmission: PublicRepositorySpoolAdmission?
    /// Shared process-wide/per-account admission for descriptor-backed public
    /// blob responses. A GET reserves before the store opens and verifies the
    /// payload, and holds the lease until the response writer finishes.
    let blobStreamAdmission: PublicRepositorySpoolAdmission

    public init(
        authorizer: SwanOAuthResourceAuthorizer,
        directory: any PublicRepositoryMutationDirectory,
        signerProvider: any PublicRepositoryMutationSignerProvider,
        blobStore: (any BlobStore)? = nil,
        publicBlobSpoolAdmission: PublicRepositorySpoolAdmission? = nil,
        blobStreamAdmission: PublicRepositorySpoolAdmission = .shared
    ) {
        self.authorizer = authorizer
        self.directory = directory
        self.signerProvider = signerProvider
        self.blobStore = blobStore
        self.publicBlobSpoolAdmission = publicBlobSpoolAdmission
        self.blobStreamAdmission = blobStreamAdmission
    }
}
