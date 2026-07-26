import Crypto
import Foundation
import SwanCore
import SwanSpaces

public enum BlobNamespace: Sendable, Hashable {
    case `public`
    case space(SpaceURI)
}

public struct BlobReference: Sendable, Hashable {
    public let cid: String
    public let namespace: BlobNamespace
    public init(cid: String, namespace: BlobNamespace) {
        self.cid = cid
        self.namespace = namespace
    }
}

public protocol BlobStore: Sendable {
    func put(_ data: Data, namespace: BlobNamespace) async throws -> BlobReference
    func data(for reference: BlobReference) async throws -> Data
    func publicData(cid: String) async throws -> Data?
    func remove(_ reference: BlobReference) async throws
}

/// Local immutable content-addressed blobs. File contents are shared, while
/// their public and permissioned reachability is tracked separately.
public actor FileBlobStore: BlobStore {
    private let root: URL
    private var references: [String: Set<BlobNamespace>] = [:]

    public init(root: URL) throws {
        self.root = root
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    }

    public func put(_ data: Data, namespace: BlobNamespace) throws -> BlobReference {
        let cid = "sha256:\(Hex.encode(SHA256.hash(data: data)))"
        let file = fileURL(for: cid)
        if !FileManager.default.fileExists(atPath: file.path) {
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: file, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        }
        references[cid, default: []].insert(namespace)
        return BlobReference(cid: cid, namespace: namespace)
    }

    public func data(for reference: BlobReference) throws -> Data {
        guard references[reference.cid, default: []].contains(reference.namespace) else {
            throw SwanError.unauthorized("blob reference is not reachable in this namespace")
        }
        return try Data(contentsOf: fileURL(for: reference.cid))
    }

    public func publicData(cid: String) throws -> Data? {
        guard references[cid, default: []].contains(.public) else { return nil }
        return try Data(contentsOf: fileURL(for: cid))
    }

    public func remove(_ reference: BlobReference) throws {
        guard var namespaces = references[reference.cid] else { return }
        namespaces.remove(reference.namespace)
        if namespaces.isEmpty {
            references.removeValue(forKey: reference.cid)
            try? FileManager.default.removeItem(at: fileURL(for: reference.cid))
        } else {
            references[reference.cid] = namespaces
        }
    }

    private func fileURL(for cid: String) -> URL {
        let digest = String(cid.dropFirst("sha256:".count))
        return root.appending(path: String(digest.prefix(2))).appending(path: digest)
    }
}

public struct OutboxEvent: Sendable, Equatable, Identifiable {
    public let id: UUID
    public let space: SpaceURI
    public let revision: UInt64
    public let payload: Data
    public let createdAt: Date
    public var attempts: Int

    public init(id: UUID = UUID(), space: SpaceURI, revision: UInt64, payload: Data, createdAt: Date = Date(), attempts: Int = 0) {
        self.id = id
        self.space = space
        self.revision = revision
        self.payload = payload
        self.createdAt = createdAt
        self.attempts = attempts
    }
}

public actor TransactionalOutbox {
    private var pending: [UUID: OutboxEvent] = [:]

    public init() {}

    public func enqueue(_ event: OutboxEvent) {
        pending[event.id] = event
    }

    public func next(limit: Int = 100) -> [OutboxEvent] {
        pending.values.sorted { $0.createdAt < $1.createdAt }.prefix(limit).map { $0 }
    }

    public func markDelivered(_ id: UUID) { pending.removeValue(forKey: id) }

    public func markAttempt(_ id: UUID) {
        guard var event = pending[id] else { return }
        event.attempts += 1
        pending[id] = event
    }
}

/// This protocol is intentionally expressed in repository domain terms instead
/// of as a generic key/value API. SQLite is the first implementation and a
/// FoundationDB adapter may implement the same transaction boundary later.
public protocol AccountRepositoryStore: Sendable {
    func repository(for space: SpaceURI, author: String) async throws -> SpaceRepository
}

public actor InMemoryAccountRepositoryStore: AccountRepositoryStore {
    private struct RepositoryKey: Hashable {
        let space: SpaceURI
        let author: String
    }

    private var repositories: [RepositoryKey: SpaceRepository] = [:]
    private let retention: Int

    public init(retention: Int = 10_000) { self.retention = retention }

    public func repository(for space: SpaceURI, author: String) throws -> SpaceRepository {
        let key = RepositoryKey(space: space, author: author)
        if let repository = repositories[key] { return repository }
        let repository = try SpaceRepository(space: space, author: author, retention: retention)
        repositories[key] = repository
        return repository
    }
}

/// Coordinates in-process work only. Durable conflict detection belongs to
/// the storage transaction, so callers must continue to pass expected CIDs or
/// revisions when a concrete database backend is introduced.
public actor AccountCoordinator {
    private let store: any AccountRepositoryStore
    public init(store: any AccountRepositoryStore) { self.store = store }

    public func repository(for space: SpaceURI, author: String) async throws -> SpaceRepository {
        try await store.repository(for: space, author: author)
    }
}
