import Foundation
import Petrel
import SwanPublicRepository

public enum PublicRepositoryReadError: Error, Sendable, Equatable {
    case invalidSelector
    case invalidLimit
    case invalidCursor
    case unavailable
}

public struct PublicPLCGenesisFacts: Sendable, Equatable {
    public let signingDIDKey: String
    public let rotationDIDKey: String
    public let canonicalHandle: String
    public let pdsOrigin: String
    public let signature: String

    public init(
        signingDIDKey: String,
        rotationDIDKey: String,
        canonicalHandle: String,
        pdsOrigin: String,
        signature: String
    ) {
        self.signingDIDKey = signingDIDKey
        self.rotationDIDKey = rotationDIDKey
        self.canonicalHandle = canonicalHandle
        self.pdsOrigin = pdsOrigin
        self.signature = signature
    }
}

/// Acyclic adapter boundary: PLC crypto remains owned by SwanAccounts while
/// the SQLite directory consumes only a verified public operation CID.
public protocol PublicPLCGenesisVerifying: Sendable {
    func verifyGenesis(
        facts: PublicPLCGenesisFacts,
        expectedDID: String
    ) throws -> String
}

/// Public PLC identity facts authenticated during provisioning and stored
/// beside the account repository. This deliberately carries no private key
/// material and is the only identity source accepted by `describeRepo`.
public struct PublicRepositoryReadIdentity: Sendable, Equatable {
    public let canonicalHandle: String
    public let pdsOrigin: String
    public let signingDIDKey: String
    public let handleIsCorrect: Bool
    public let preparationRequestID: String
    public let genesisOperationCID: String

    public init(
        canonicalHandle: String,
        pdsOrigin: String,
        signingDIDKey: String,
        handleIsCorrect: Bool,
        preparationRequestID: String,
        genesisOperationCID: String
    ) throws {
        guard AccountControlIdentifiers.isCanonicalHandle(canonicalHandle),
              let origin = URL(string: pdsOrigin),
              origin.scheme == "https",
              origin.host != nil,
              origin.path.isEmpty || origin.path == "/",
              origin.query == nil,
              origin.fragment == nil,
              signingDIDKey.hasPrefix("did:key:z"),
              signingDIDKey.count == 57,
              !preparationRequestID.isEmpty,
              (try? CID.parse(genesisOperationCID)) != nil else {
            throw PublicRepositoryReadError.unavailable
        }
        self.canonicalHandle = canonicalHandle
        self.pdsOrigin = pdsOrigin
        self.signingDIDKey = signingDIDKey
        self.handleIsCorrect = handleIsCorrect
        self.preparationRequestID = preparationRequestID
        self.genesisOperationCID = genesisOperationCID
    }
}

/// A public-only account and repository projection. Its shape cannot carry
/// credentials, keys, OAuth state, permissioned repository data, blob
/// namespaces, or a storage handle.
public struct PublicRepositoryReadDescription: Sendable, Equatable {
    public let did: String
    public let canonicalHandle: String
    public let status: AccountControlStatus
    public let state: PublicRepositoryState
    public let collections: [String]
    public let identity: PublicRepositoryReadIdentity

    public init(
        did: String,
        canonicalHandle: String,
        status: AccountControlStatus,
        state: PublicRepositoryState,
        collections: [String],
        identity: PublicRepositoryReadIdentity
    ) throws {
        guard AccountControlIdentifiers.isDID(did),
              AccountControlIdentifiers.isCanonicalHandle(canonicalHandle),
              status.isCanonicalValue,
              state.did == did,
              collections == Array(Set(collections)).sorted(),
              collections.allSatisfy({
                  (try? PublicRepositoryPath(
                      collection: $0,
                      recordKey: "validation"
                  )) != nil
              }) else {
            throw PublicRepositoryReadError.unavailable
        }
        self.did = did
        self.canonicalHandle = canonicalHandle
        self.status = status
        self.state = state
        self.collections = collections
        self.identity = identity
    }
}

public struct PublicRepositoryReadStatus: Sendable, Equatable {
    public let did: String
    public let status: AccountControlStatus
    public let revision: String?

    public init(did: String, status: AccountControlStatus, revision: String?) throws {
        guard AccountControlIdentifiers.isDID(did), status.isCanonicalValue,
              revision == nil || (try? PublicRepositoryTID(revision!)) != nil,
              status == .active || revision == nil else {
            throw PublicRepositoryReadError.unavailable
        }
        self.did = did
        self.status = status
        self.revision = revision
    }
}

public struct PublicRepositoryReadRecord: Sendable, Equatable {
    public let path: PublicRepositoryPath
    public let cid: CID
    public let canonicalBytes: Data

    public init(path: PublicRepositoryPath, cid: CID, canonicalBytes: Data) throws {
        do {
            try PublicRepositoryCID.validate(cid, blockBytes: canonicalBytes)
            try RepositoryMSTValidation.validateRecordBlock(
                canonicalBytes, for: path
            )
        } catch {
            throw PublicRepositoryReadError.unavailable
        }
        self.path = path
        self.cid = cid
        self.canonicalBytes = canonicalBytes
    }
}

public struct PublicRepositoryReadPage: Sendable, Equatable {
    public let records: [PublicRepositoryReadRecord]
    public let cursor: String?

    public init(records: [PublicRepositoryReadRecord], cursor: String?) throws {
        let paths = records.map(\.path.mstKey)
        guard Set(paths).count == paths.count,
              cursor == nil || !cursor!.isEmpty else {
            throw PublicRepositoryReadError.unavailable
        }
        self.records = records
        self.cursor = cursor
    }
}

/// Process-wide and per-account admission for disk-backed CAR spools. Each
/// request reserves its worst-case size before creating a file, bounding both
/// disk amplification and the number of slow consumers.
public final class PublicRepositorySpoolAdmission: @unchecked Sendable {
    public struct Snapshot: Sendable, Equatable {
        public let reservedBytes: Int
        public let activeLeases: Int
        public let reservedBytesByAccount: [String: Int]

        public init(
            reservedBytes: Int,
            activeLeases: Int,
            reservedBytesByAccount: [String: Int]
        ) {
            self.reservedBytes = reservedBytes
            self.activeLeases = activeLeases
            self.reservedBytesByAccount = reservedBytesByAccount
        }
    }

    private let maximumGlobalBytes: Int
    private let maximumPerAccountBytes: Int
    private let lock = NSLock()
    private var leases: [UUID: (account: String, bytes: Int)] = [:]
    private var reservedByAccount: [String: Int] = [:]

    public init(
        maximumGlobalBytes: Int = 1_024 * 1_024 * 1_024,
        maximumPerAccountBytes: Int = 512 * 1_024 * 1_024
    ) throws {
        guard maximumGlobalBytes > 0,
              maximumPerAccountBytes > 0,
              maximumPerAccountBytes <= maximumGlobalBytes else {
            throw PublicRepositoryReadError.unavailable
        }
        self.maximumGlobalBytes = maximumGlobalBytes
        self.maximumPerAccountBytes = maximumPerAccountBytes
    }

    public func reserve(
        accountDID: String,
        maximumBytes: Int
    ) -> PublicRepositorySpoolLease? {
        guard AccountControlIdentifiers.isDID(accountDID),
              maximumBytes > 0 else { return nil }
        return lock.withLock {
            let global = leases.values.reduce(0) { $0 + $1.bytes }
            let account = reservedByAccount[accountDID, default: 0]
            guard maximumBytes <= maximumGlobalBytes - global,
                  maximumBytes <= maximumPerAccountBytes - account else {
                return nil
            }
            let id = UUID()
            leases[id] = (accountDID, maximumBytes)
            reservedByAccount[accountDID] = account + maximumBytes
            return PublicRepositorySpoolLease(admission: self, id: id)
        }
    }

    public var snapshot: Snapshot {
        lock.withLock {
            Snapshot(
                reservedBytes: leases.values.reduce(0) { $0 + $1.bytes },
                activeLeases: leases.count,
                reservedBytesByAccount: reservedByAccount
            )
        }
    }

    fileprivate func release(_ id: UUID) {
        lock.withLock {
            guard let lease = leases.removeValue(forKey: id) else { return }
            let remaining = reservedByAccount[lease.account, default: 0] - lease.bytes
            if remaining == 0 {
                reservedByAccount.removeValue(forKey: lease.account)
            } else {
                reservedByAccount[lease.account] = remaining
            }
        }
    }
}

public final class PublicRepositorySpoolLease: @unchecked Sendable {
    private weak var admission: PublicRepositorySpoolAdmission?
    private let id: UUID
    private let lock = NSLock()
    private var released = false

    fileprivate init(admission: PublicRepositorySpoolAdmission, id: UUID) {
        self.admission = admission
        self.id = id
    }

    deinit { release() }

    public func release() {
        let target = lock.withLock {
            guard !released else { return nil as PublicRepositorySpoolAdmission? }
            released = true
            return admission
        }
        target?.release(id)
    }
}

/// Owner-only descriptor-backed CAR body. The path is never exposed to HTTP;
/// consumers can only drain bounded chunks, and every terminal path removes
/// the file.
public final class PublicRepositoryCARSpool: @unchecked Sendable {
    public static let maximumChunkBytes = 64 * 1_024

    private let handle: FileHandle
    private let lease: PublicRepositorySpoolLease
    private let lock = NSLock()
    private enum State { case available, streaming, cleaned }
    private var state: State = .available

    /// Adopts an already-open, read-positioned descriptor. The producer must
    /// validate it as an owner-only regular file and unlink its pathname
    /// before crossing this boundary, eliminating replacement/symlink races.
    package init(fileHandle: FileHandle, lease: PublicRepositorySpoolLease) {
        handle = fileHandle
        self.lease = lease
    }

    deinit { cleanup() }

    public var isCleanedUp: Bool {
        lock.withLock { state == .cleaned }
    }

    public func stream(
        maximumChunkBytes: Int = 64 * 1_024,
        consume: (Data) async throws -> Void
    ) async throws {
        guard (1...Self.maximumChunkBytes).contains(maximumChunkBytes) else {
            cleanup()
            throw PublicRepositoryReadError.unavailable
        }
        let admitted = lock.withLock {
            guard state == .available else { return false }
            state = .streaming
            return true
        }
        guard admitted else {
            cleanup()
            throw PublicRepositoryReadError.unavailable
        }
        defer {
            try? handle.close()
            cleanup()
        }
        while true {
            try Task.checkCancellation()
            guard let chunk = try handle.read(upToCount: maximumChunkBytes),
                  !chunk.isEmpty else { return }
            try await consume(chunk)
        }
    }

    public func cleanup() {
        let shouldClose = lock.withLock {
            guard state != .cleaned else { return false }
            state = .cleaned
            return true
        }
        if shouldClose {
            try? handle.close()
            lease.release()
        }
    }
}

public struct PublicRepositoryReadCAR: Sendable {
    public let state: PublicRepositoryState
    public let spool: PublicRepositoryCARSpool

    package init(state: PublicRepositoryState, spool: PublicRepositoryCARSpool) {
        self.state = state
        self.spool = spool
    }
}

/// Request-time selectors can only address the startup-preopened inventory.
/// Implementations must never resolve over DNS, PLC, DID, or HTTP.
public protocol PublicRepositoryReadDirectory: Sendable {
    func publicRepositoryStatus(selector: String) async throws
        -> PublicRepositoryReadStatus?
    func describePublicRepository(selector: String) async throws
        -> PublicRepositoryReadDescription?
    func publicRepositoryRecord(
        selector: String,
        path: PublicRepositoryPath,
        expectedCID: CID?
    ) async throws -> PublicRepositoryReadRecord?
    func listPublicRepositoryRecords(
        selector: String,
        collection: String,
        limit: Int,
        cursor: String?,
        reverse: Bool
    ) async throws -> PublicRepositoryReadPage
    func publicRepositoryCAR(selector: String) async throws
        -> PublicRepositoryReadCAR?
}
