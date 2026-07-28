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
    func publicBlob(cid: String) async throws -> PublicBlob?
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

    public init(
        authorizer: SwanOAuthResourceAuthorizer,
        directory: any PublicRepositoryMutationDirectory,
        signerProvider: any PublicRepositoryMutationSignerProvider,
        blobStore: (any BlobStore)? = nil
    ) {
        self.authorizer = authorizer
        self.directory = directory
        self.signerProvider = signerProvider
        self.blobStore = blobStore
    }
}
