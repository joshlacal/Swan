import Foundation
import Petrel

public struct PublicRepositoryImportEnvelope: Sendable {
    public let requestID: String
    public let requestDigest: Data
    public let did: String
    public let rootCID: CID
    public let expectedExistingRootCID: CID?
    public let blocks: [PublicRepositoryBlock]
    public let referencedBlobs: [CID]
    public let blobPayloads: [PublicRepositoryBlock]
    public let signature: Data

    public init(did: String, rootCID: CID, expectedExistingRootCID: CID? = nil, blocks: [PublicRepositoryBlock], referencedBlobs: [CID] = [], blobPayloads: [PublicRepositoryBlock] = [], signature: Data, requestID: String, requestDigest: Data) throws {
        guard !requestID.isEmpty, requestID.utf8.count <= 512, !requestID.contains("\0"), requestDigest.count == 32 else {
            throw PublicRepositoryReferenceImportError.invalidBinding
        }
        self.requestID = requestID
        self.requestDigest = requestDigest
        self.did = did
        self.rootCID = rootCID
        if let expectedExistingRootCID { try PublicRepositoryCID.validate(expectedExistingRootCID) }
        self.expectedExistingRootCID = expectedExistingRootCID
        self.blocks = blocks
        self.referencedBlobs = referencedBlobs
        self.blobPayloads = blobPayloads
        self.signature = signature
    }
}

public struct PublicRepositoryImportedState: Sendable, Equatable {
    public let did: String
    public let rootCID: CID
    public let blocks: [PublicRepositoryBlock]

    public init(did: String, rootCID: CID, blocks: [PublicRepositoryBlock]) {
        self.did = did
        self.rootCID = rootCID
        self.blocks = blocks
    }
}

public protocol PublicRepositoryImportCommitter: Sendable {
    /// False for adapters that have not yet been wired to durable storage.
    var isDurableTransactional: Bool { get }
    /// Implementations must atomically compare `expectedRootCID`, record the
    /// request digest, and either commit once or replay the same result for an
    /// identical `(requestID, requestDigest)`. A different digest for a reused
    /// request ID is a conflict; no partial blocks may remain visible.
    func commit(_ state: PublicRepositoryImportedState, requestID: String, requestDigest: Data, expectedRootCID: CID?) async throws -> PublicRepositoryImportedState
}

public protocol PublicRepositoryBlobResolver: Sendable {
    func containsBlob(_ cid: CID) async throws -> Bool
}

public enum PublicRepositoryReferenceImportError: Error, Sendable, Equatable {
    case invalidDID
    case invalidBinding
    case invalidRoot
    case blockLimitExceeded
    case byteLimitExceeded
    case duplicateBlockConflict
    case missingBlob(CID)
    case invalidSignature
    case conflictingRequestReuse
    case commitCASConflict
    case unassembled
}

/// Verifies an import completely before invoking the injected durable commit
/// boundary. No block, blob, or root is published on a failed preflight.
public struct PublicRepositoryReferenceImportVerifier: Sendable {
    public let maximumBlocks: Int
    public let maximumBytes: Int

    public init(maximumBlocks: Int = 100_000, maximumBytes: Int = 512 * 1_024 * 1_024) throws {
        guard maximumBlocks > 0, maximumBytes > 0 else { throw PublicRepositoryReferenceImportError.blockLimitExceeded }
        self.maximumBlocks = maximumBlocks
        self.maximumBytes = maximumBytes
    }

    public func verifyAndCommit(
        _ envelope: PublicRepositoryImportEnvelope,
        committer: any PublicRepositoryImportCommitter,
        existingBlobResolver: (any PublicRepositoryBlobResolver)? = nil,
        verifySignature: @escaping @Sendable (String, CID, Data) throws -> Bool
    ) async throws -> PublicRepositoryImportedState {
        guard committer.isDurableTransactional else { throw PublicRepositoryReferenceImportError.unassembled }
        guard (try? DID(didString: envelope.did)) != nil else { throw PublicRepositoryReferenceImportError.invalidDID }
        try PublicRepositoryCID.validate(envelope.rootCID)
        for blob in envelope.referencedBlobs { try PublicRepositoryCID.validate(blob) }
        guard envelope.blocks.count + envelope.blobPayloads.count <= maximumBlocks else { throw PublicRepositoryReferenceImportError.blockLimitExceeded }
        var totalBytes = 0
        for block in envelope.blocks {
            let (next, overflow) = totalBytes.addingReportingOverflow(block.bytes.count)
            guard !overflow, next <= maximumBytes else { throw PublicRepositoryReferenceImportError.byteLimitExceeded }
            totalBytes = next
        }
        for block in envelope.blobPayloads {
            let (next, overflow) = totalBytes.addingReportingOverflow(block.bytes.count)
            guard !overflow, next <= maximumBytes else { throw PublicRepositoryReferenceImportError.byteLimitExceeded }
            totalBytes = next
        }
        guard try verifySignature(envelope.did, envelope.rootCID, envelope.signature) else { throw PublicRepositoryReferenceImportError.invalidSignature }

        var byCID: [CID: Data] = [:]
        for block in envelope.blocks {
            try PublicRepositoryCID.validate(block.cid, blockBytes: block.bytes)
            if let existing = byCID[block.cid], existing != block.bytes { throw PublicRepositoryReferenceImportError.duplicateBlockConflict }
            byCID[block.cid] = block.bytes
        }
        for block in envelope.blobPayloads {
            try PublicRepositoryCID.validate(block.cid, blockBytes: block.bytes)
            if let existing = byCID[block.cid], existing != block.bytes { throw PublicRepositoryReferenceImportError.duplicateBlockConflict }
            byCID[block.cid] = block.bytes
        }
        guard byCID[envelope.rootCID] != nil else { throw PublicRepositoryReferenceImportError.invalidRoot }
        for blob in Set(envelope.referencedBlobs) where byCID[blob] == nil {
            guard try await existingBlobResolver?.containsBlob(blob) == true else {
                throw PublicRepositoryReferenceImportError.missingBlob(blob)
            }
        }
        let state = PublicRepositoryImportedState(did: envelope.did, rootCID: envelope.rootCID, blocks: byCID.map { .init(cid: $0.key, bytes: $0.value) }.sorted { $0.cid.description < $1.cid.description })
        return try await committer.commit(state, requestID: envelope.requestID, requestDigest: envelope.requestDigest, expectedRootCID: envelope.expectedExistingRootCID)
    }
}

/// A small actor model used by focused contract tests and local acceptance.
/// Real SQLite adapters must provide the same atomic request-digest/CAS
/// behavior inside their transaction; this model is not production storage.
public actor InMemoryPublicRepositoryImportCommitter: PublicRepositoryImportCommitter {
    public let isDurableTransactional = true
    private var currentRootCID: CID?
    private var requests: [String: (digest: Data, state: PublicRepositoryImportedState)] = [:]

    public init(currentRootCID: CID? = nil) { self.currentRootCID = currentRootCID }

    public func commit(_ state: PublicRepositoryImportedState, requestID: String, requestDigest: Data, expectedRootCID: CID?) async throws -> PublicRepositoryImportedState {
        guard requestDigest.count == 32 else { throw PublicRepositoryReferenceImportError.invalidBinding }
        if let prior = requests[requestID] {
            guard prior.digest == requestDigest else { throw PublicRepositoryReferenceImportError.conflictingRequestReuse }
            return prior.state
        }
        if let expectedRootCID, currentRootCID != expectedRootCID { throw PublicRepositoryReferenceImportError.commitCASConflict }
        requests[requestID] = (requestDigest, state)
        currentRootCID = state.rootCID
        return state
    }

    public func rootCID() -> CID? { currentRootCID }
}
