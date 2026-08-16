import Foundation
import Petrel

public enum PublicRepositoryReferenceSurfaceError: Error, Sendable, Equatable {
    case invalidLimit
    case invalidCursor
    case tooManySelectors
    case missingRecord
    case missingBlock
    case invalidBinding
}

public struct PublicRepositorySyncRepository: Sendable, Equatable {
    public let did: String
    public let head: CID
    public let rev: String

    public init(did: String, head: CID, rev: String) throws {
        guard (try? DID(didString: did)) != nil else { throw PublicRepositoryReferenceSurfaceError.invalidBinding }
        try PublicRepositoryCID.validate(head)
        _ = try PublicRepositoryTID(rev)
        self.did = did
        self.head = head
        self.rev = rev
    }
}

public struct PublicRepositoryRecordIndexEntry: Sendable, Equatable {
    public let path: PublicRepositoryPath
    public let cid: CID

    public init(path: PublicRepositoryPath, cid: CID) throws {
        try PublicRepositoryCID.validate(cid)
        self.path = path
        self.cid = cid
    }
}

public struct PublicRepositorySyncRepoPage: Sendable, Equatable {
    public let repos: [PublicRepositorySyncRepository]
    public let cursor: String?
}

public struct PublicRepositorySyncBlockPage: Sendable, Equatable {
    public let blocks: [PublicRepositoryBlock]
    public let missing: [CID]
    public let cursor: String?
}

public struct PublicRepositorySyncRecord: Sendable, Equatable {
    public let path: PublicRepositoryPath
    public let cid: CID
    public let bytes: Data
}

public struct PublicRepositorySyncBlobPage: Sendable, Equatable {
    public let blobs: [CID]
    public let cursor: String?
}

/// A bounded, storage-neutral implementation of the reference sync/repo
/// enumeration semantics. The HTTP adapters can map these projections to the
/// generated wire types without granting a caller an unbounded block or blob
/// query.
public actor PublicRepositoryReferenceSurface {
    private let repositories: [PublicRepositorySyncRepository]
    private let blocks: [CID: Data]
    private let records: [PublicRepositoryPath: CID]
    private let maximumPageSize: Int

    public init(
        did: String,
        revision: String,
        blocks: [PublicRepositoryBlock],
        records: [PublicRepositoryRecordIndexEntry],
        blobs: [CID] = [],
        repositories: [PublicRepositorySyncRepository]? = nil,
        maximumPageSize: Int = 100
    ) throws {
        guard (1...1_000).contains(maximumPageSize) else { throw PublicRepositoryReferenceSurfaceError.invalidLimit }
        let map = try PublicRepositoryBlockMap(blocks: blocks)
        let repository = try PublicRepositorySyncRepository(
            did: did,
            head: PlaceholderCID.unavailable,
            rev: revision
        )
        // A repository head is not needed by enumeration callers. Keep a
        // validated projection while deriving it from the first supplied
        // block when a caller does not provide a multi-repository fixture.
        let fallbackHead = blocks.first?.cid ?? repository.head
        let fallback = try PublicRepositorySyncRepository(did: did, head: fallbackHead, rev: revision)
        self.repositories = (repositories ?? [fallback]).sorted { $0.did < $1.did }
        self.blocks = Dictionary(uniqueKeysWithValues: map.cids.compactMap { cid in map.block(for: cid).map { (cid, $0) } })
        self.records = Dictionary(uniqueKeysWithValues: records.map { ($0.path, $0.cid) })
        self.maximumPageSize = maximumPageSize
        self.blobCIDs = Set(blobs)
    }

    private let blobCIDs: Set<CID>

    public func listRepos(limit: Int = 100, cursor: String? = nil) throws -> PublicRepositorySyncRepoPage {
        let range = try pageRange(count: repositories.count, limit: limit, cursor: cursor)
        let values = Array(repositories[range])
        return .init(repos: values, cursor: nextCursor(end: range.upperBound, count: repositories.count))
    }

    public func getBlocks(_ cids: [CID], limit: Int = 100, cursor: String? = nil) throws -> PublicRepositorySyncBlockPage {
        guard cids.count <= 10_000 else { throw PublicRepositoryReferenceSurfaceError.tooManySelectors }
        let range = try pageRange(count: cids.count, limit: limit, cursor: cursor)
        var found: [PublicRepositoryBlock] = []
        var missing: [CID] = []
        for cid in cids[range] {
            if let bytes = blocks[cid] { found.append(.init(cid: cid, bytes: bytes)) } else { missing.append(cid) }
        }
        return .init(blocks: found, missing: missing, cursor: nextCursor(end: range.upperBound, count: cids.count))
    }

    public func getRecord(path: PublicRepositoryPath) throws -> PublicRepositorySyncRecord {
        guard let cid = records[path], let bytes = blocks[cid] else { throw PublicRepositoryReferenceSurfaceError.missingRecord }
        return .init(path: path, cid: cid, bytes: bytes)
    }

    public func listBlobs(limit: Int = 100, cursor: String? = nil) throws -> PublicRepositorySyncBlobPage {
        let values = blobCIDs.sorted { $0.description < $1.description }
        let range = try pageRange(count: values.count, limit: limit, cursor: cursor)
        return .init(blobs: Array(values[range]), cursor: nextCursor(end: range.upperBound, count: values.count))
    }

    public func listMissingBlobs(_ cids: [CID], limit: Int = 100, cursor: String? = nil) throws -> PublicRepositorySyncBlobPage {
        guard cids.count <= 10_000 else { throw PublicRepositoryReferenceSurfaceError.tooManySelectors }
        var seen = Set<CID>()
        let missing = cids.filter { blocks[$0] == nil && seen.insert($0).inserted }
        let range = try pageRange(count: missing.count, limit: limit, cursor: cursor)
        return .init(blobs: Array(missing[range]), cursor: nextCursor(end: range.upperBound, count: missing.count))
    }

    private func pageRange(count: Int, limit: Int, cursor: String?) throws -> Range<Int> {
        guard (1...maximumPageSize).contains(limit) else { throw PublicRepositoryReferenceSurfaceError.invalidLimit }
        let start: Int
        if let cursor {
            guard let parsed = Int(cursor), parsed >= 0, parsed <= count else { throw PublicRepositoryReferenceSurfaceError.invalidCursor }
            start = parsed
        } else { start = 0 }
        return start ..< min(start + limit, count)
    }

    private func nextCursor(end: Int, count: Int) -> String? { end < count ? String(end) : nil }
}

private enum PlaceholderCID {
    static var unavailable: CID {
        CID.fromDAGCBOR(Data([0xa0]))
    }
}
