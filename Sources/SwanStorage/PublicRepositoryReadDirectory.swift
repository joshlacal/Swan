import Foundation
import Petrel
import SwanPublicRepository

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public enum PublicRepositoryReadError: Error, Sendable, Equatable {
    case invalidSelector
    case invalidLimit
    case invalidCursor
    case resourceLimitExceeded
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

/// The authenticated result of binding one repository head to the terminal
/// `atproto` verification method in an already-verified PLC identity.
///
/// SQLite owns repository state and projection validation, while SwanAccounts
/// owns DID-key decoding and signature algorithms. Keeping this narrow value
/// in SwanStorage avoids making either layer depend on the other's concrete
/// implementation.
public struct PublicRepositoryCommitAuthentication: Sendable, Equatable {
    public let descriptor: PublicRepositoryCommitDescriptor
    public let commitCID: CID
    public let verificationIdentity: String

    public init(
        descriptor: PublicRepositoryCommitDescriptor,
        commitCID: CID,
        verificationIdentity: String
    ) throws {
        guard descriptor.did.hasPrefix("did:"),
              !verificationIdentity.isEmpty,
              verificationIdentity.utf8.count <= 256 else {
            throw PublicRepositoryReadError.unavailable
        }
        do {
            try PublicRepositoryCID.validate(commitCID)
        } catch {
            throw PublicRepositoryReadError.unavailable
        }
        self.descriptor = descriptor
        self.commitCID = commitCID
        self.verificationIdentity = verificationIdentity
    }
}

/// Local-crypto capability used only after PLC genesis/history validation has
/// selected the terminal signing DID key. Implementations must verify the
/// canonical commit signature; structural CBOR/CID validation alone is not
/// sufficient to make a repository publicly reachable.
public protocol PublicPLCRepositoryAuthenticating:
    PublicPLCGenesisVerifying
{
    func authenticateRepositoryCommit(
        signedCommitBytes: Data,
        expectedCommitCID: CID,
        expectedDID: String,
        signingDIDKey: String
    ) async throws -> PublicRepositoryCommitAuthentication
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
    public let terminalOperationCID: String

    public init(
        canonicalHandle: String,
        pdsOrigin: String,
        signingDIDKey: String,
        handleIsCorrect: Bool,
        preparationRequestID: String,
        genesisOperationCID: String,
        terminalOperationCID: String? = nil
    ) throws {
        guard AccountControlIdentifiers.isCanonicalHandle(canonicalHandle),
              let origin = URL(string: pdsOrigin),
              origin.scheme == "https",
              origin.host != nil,
              origin.path.isEmpty || origin.path == "/",
              origin.query == nil,
              origin.fragment == nil,
              signingDIDKey.hasPrefix("did:key:z"),
              signingDIDKey.utf8.count <= 256,
              !preparationRequestID.isEmpty,
              (try? CID.parse(genesisOperationCID)) != nil,
              (try? CID.parse(terminalOperationCID ?? genesisOperationCID)) != nil else {
            throw PublicRepositoryReadError.unavailable
        }
        self.canonicalHandle = canonicalHandle
        self.pdsOrigin = pdsOrigin
        self.signingDIDKey = signingDIDKey
        self.handleIsCorrect = handleIsCorrect
        self.preparationRequestID = preparationRequestID
        self.genesisOperationCID = genesisOperationCID
        self.terminalOperationCID = terminalOperationCID ?? genesisOperationCID
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
        guard collections.count <= PublicRepositoryReadLimits
            .maximumDescribeRepoCollections else {
            throw PublicRepositoryReadError.resourceLimitExceeded
        }
        var collectionBytes = 0
        for collection in collections {
            let (next, overflow) = collectionBytes.addingReportingOverflow(
                collection.utf8.count
            )
            guard !overflow,
                  collection.utf8.count <= Int(
                      PublicRepositoryReadLimits.maximumDescribeRepoCollectionBytes
                  ),
                  next <= PublicRepositoryReadLimits
                      .maximumDescribeRepoCollectionBytes else {
                throw PublicRepositoryReadError.resourceLimitExceeded
            }
            collectionBytes = next
        }
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

/// Hard response-allocation limits for the unauthenticated public JSON
/// endpoints. A list page can contain fewer records than the requested count;
/// callers continue from its last-record cursor. This keeps pagination
/// interoperable while bounding canonical input and encoded output separately.
public enum PublicRepositoryJSONReadLimits {
    public static let maximumAggregateRecordBlockBytes = 4 * 1_024 * 1_024
    public static let maximumGetRecordResponseBytes = 8 * 1_024 * 1_024
    public static let maximumListRecordsResponseBytes = 16 * 1_024 * 1_024
    /// Value-bearing permissioned oplog pages are encoded as JSON rather than
    /// streamed CARs. Keep their live-value aggregate below the response
    /// ceiling so the storage query and encoder never retain a worst-case page
    /// larger than the final HTTP budget.
    public static let maximumListRepoOpsValueBytes = 8 * 1_024 * 1_024
    /// Same-TID batches are returned atomically, so cap their metadata as well
    /// as their live-value bytes. A pathological oversized batch fails closed
    /// instead of allocating an unbounded operation array.
    public static let maximumListRepoOpsOperations = 4_096
}

/// Explicit bounds for public-repository projections that are prepared before
/// an anonymous request can read them. These are Swan availability policy, not
/// changes to repository-v3 semantics: an account exceeding them remains
/// valid repository data but is not exposed through the alpha public surface.
public enum PublicRepositoryReadLimits {
    /// Keeps startup/mutation admission's SQLite index and MST leaf metadata
    /// below the whole-repository retained-block validator's larger import
    /// ceiling.
    public static let maximumGenerationIndexEntries = 100_000

    /// `describeRepo` must be encodable well below the 16 MiB anonymous JSON
    /// response budget, including quotes, commas, and fixed DID-document data.
    public static let maximumDescribeRepoCollections = 100_000
    public static let maximumDescribeRepoCollectionBytes = 8 * 1_024 * 1_024

    /// Blob promotion is an optional operator/interop helper. Page the index
    /// and refuse a repository whose record or unique-blob set exceeds these
    /// bounds instead of retaining an unbounded projection in the process.
    public static let maximumBlobPromotionIndexEntries = 100_000
    public static let maximumBlobPromotionUniqueCIDs = 100_000
    public static let blobPromotionPageSize = 256
    public static let projectionPreflightPageSize = 256
}

public struct PublicRepositoryReadPage: Sendable, Equatable {
    public let records: [PublicRepositoryReadRecord]
    public let cursor: String?

    public init(records: [PublicRepositoryReadRecord], cursor: String?) throws {
        let paths = records.map(\.path.mstKey)
        var aggregateBytes = 0
        for record in records {
            let (next, overflow) = aggregateBytes.addingReportingOverflow(
                record.canonicalBytes.count
            )
            guard !overflow,
                  next <= PublicRepositoryJSONReadLimits
                    .maximumAggregateRecordBlockBytes else {
                throw PublicRepositoryReadError.unavailable
            }
            aggregateBytes = next
        }
        guard Set(paths).count == paths.count,
              cursor == nil || !cursor!.isEmpty else {
            throw PublicRepositoryReadError.unavailable
        }
        self.records = records
        self.cursor = cursor
    }
}

/// Process-wide admission for the allocation-heavy anonymous get/list JSON
/// paths. Every request reserves its worst-case encoded response before it can
/// enter a repository actor, bounding both simultaneous decoders and aggregate
/// response buffers.
public final class PublicRepositoryJSONReadAdmission: @unchecked Sendable {
    public struct Snapshot: Sendable, Equatable {
        public let activeLeases: Int
        public let reservedResponseBytes: Int

        public init(activeLeases: Int, reservedResponseBytes: Int) {
            self.activeLeases = activeLeases
            self.reservedResponseBytes = reservedResponseBytes
        }
    }

    /// One admission shared by every production router in this process.
    public static let processShared = try! PublicRepositoryJSONReadAdmission()

    private let maximumConcurrentReads: Int
    private let maximumReservedResponseBytes: Int
    // Safety invariant: `leases` is read or mutated only while `lock` is held.
    // Follow-up: replace the unchecked class boundary with the standard-library
    // Mutex once Swan's minimum Linux toolchain exposes it consistently.
    private let lock = NSLock()
    private var leases: [UUID: Int] = [:]

    public init(
        maximumConcurrentReads: Int = 8,
        maximumReservedResponseBytes: Int = 64 * 1_024 * 1_024
    ) throws {
        guard maximumConcurrentReads > 0,
              maximumReservedResponseBytes
                >= PublicRepositoryJSONReadLimits
                    .maximumListRecordsResponseBytes else {
            throw PublicRepositoryReadError.unavailable
        }
        self.maximumConcurrentReads = maximumConcurrentReads
        self.maximumReservedResponseBytes = maximumReservedResponseBytes
    }

    public func reserve(
        maximumResponseBytes: Int
    ) -> PublicRepositoryJSONReadLease? {
        guard maximumResponseBytes > 0 else { return nil }
        return lock.withLock {
            let reserved = leases.values.reduce(0, +)
            guard leases.count < maximumConcurrentReads,
                  maximumResponseBytes
                    <= maximumReservedResponseBytes - reserved else {
                return nil
            }
            let id = UUID()
            leases[id] = maximumResponseBytes
            return PublicRepositoryJSONReadLease(admission: self, id: id)
        }
    }

    public var snapshot: Snapshot {
        lock.withLock {
            Snapshot(
                activeLeases: leases.count,
                reservedResponseBytes: leases.values.reduce(0, +)
            )
        }
    }

    fileprivate func release(_ id: UUID) {
        lock.withLock {
            _ = leases.removeValue(forKey: id)
        }
    }
}

public final class PublicRepositoryJSONReadLease: @unchecked Sendable {
    private weak var admission: PublicRepositoryJSONReadAdmission?
    private let id: UUID
    // Safety invariant: `released` is accessed only while `lock` is held.
    private let lock = NSLock()
    private var released = false

    fileprivate init(admission: PublicRepositoryJSONReadAdmission, id: UUID) {
        self.admission = admission
        self.id = id
    }

    deinit { release() }

    public func release() {
        let target = lock.withLock {
            guard !released else {
                return nil as PublicRepositoryJSONReadAdmission?
            }
            released = true
            return admission
        }
        target?.release(id)
    }
}

/// Process-wide admission for allocation-heavy JSON command bodies. A write
/// route reserves its declared maximum body size before collecting any bytes
/// and holds the lease through strict parsing and typed decoding. Sharing one
/// instance across public and permissioned routes bounds aggregate anonymous
/// pre-authorization memory independently of the listener connection limit.
public final class PublicRepositoryJSONWriteAdmission: @unchecked Sendable {
    public struct Snapshot: Sendable, Equatable {
        public let activeLeases: Int
        public let reservedRequestBytes: Int

        public init(activeLeases: Int, reservedRequestBytes: Int) {
            self.activeLeases = activeLeases
            self.reservedRequestBytes = reservedRequestBytes
        }
    }

    public static let processShared = try! PublicRepositoryJSONWriteAdmission()

    /// Reserved process-wide capacity for the loopback-only operator listener.
    /// Public routes must never receive this instance: keeping it distinct from
    /// ``processShared`` prevents anonymous writes from starving emergency
    /// suspension, account lifecycle, and other authenticated operator work.
    public static let managementProcessShared = try! PublicRepositoryJSONWriteAdmission()

    private let maximumConcurrentWrites: Int
    private let maximumReservedRequestBytes: Int
    private let lock = NSLock()
    private var leases: [UUID: Int] = [:]

    public init(
        maximumConcurrentWrites: Int = 8,
        maximumReservedRequestBytes: Int = 8 * 1_024 * 1_024
    ) throws {
        guard maximumConcurrentWrites > 0,
              maximumReservedRequestBytes > 0 else {
            throw PublicRepositoryReadError.unavailable
        }
        self.maximumConcurrentWrites = maximumConcurrentWrites
        self.maximumReservedRequestBytes = maximumReservedRequestBytes
    }

    public func reserve(
        maximumRequestBytes: Int
    ) -> PublicRepositoryJSONWriteLease? {
        guard maximumRequestBytes > 0 else { return nil }
        return lock.withLock {
            let reserved = leases.values.reduce(0, +)
            guard leases.count < maximumConcurrentWrites,
                  maximumRequestBytes <= maximumReservedRequestBytes - reserved else {
                return nil
            }
            let id = UUID()
            leases[id] = maximumRequestBytes
            return PublicRepositoryJSONWriteLease(admission: self, id: id)
        }
    }

    public var snapshot: Snapshot {
        lock.withLock {
            Snapshot(
                activeLeases: leases.count,
                reservedRequestBytes: leases.values.reduce(0, +)
            )
        }
    }

    fileprivate func releaseWrite(_ id: UUID) {
        lock.withLock {
            _ = leases.removeValue(forKey: id)
        }
    }
}

public final class PublicRepositoryJSONWriteLease: @unchecked Sendable {
    private weak var admission: PublicRepositoryJSONWriteAdmission?
    private let id: UUID
    private let lock = NSLock()
    private var released = false

    fileprivate init(admission: PublicRepositoryJSONWriteAdmission, id: UUID) {
        self.admission = admission
        self.id = id
    }

    deinit { release() }

    public func release() {
        let target = lock.withLock {
            guard !released else {
                return nil as PublicRepositoryJSONWriteAdmission?
            }
            released = true
            return admission
        }
        target?.releaseWrite(id)
    }
}

/// One selector resolution and lifecycle decision for a public endpoint.
/// Keeping these facts in the same result prevents HTTP adapters from making
/// a second directory call against a different control/repository snapshot.
public enum PublicRepositoryReadOutcome<Value: Sendable>: Sendable {
    case notFound
    case lifecycle(PublicRepositoryReadStatus)
    case active(Value)
}

public struct PublicRepositoryReadRecordResult: Sendable, Equatable {
    public let did: String
    public let state: PublicRepositoryState
    public let record: PublicRepositoryReadRecord?

    public init(
        did: String,
        state: PublicRepositoryState,
        record: PublicRepositoryReadRecord?
    ) throws {
        guard AccountControlIdentifiers.isDID(did), state.did == did else {
            throw PublicRepositoryReadError.unavailable
        }
        self.did = did
        self.state = state
        self.record = record
    }
}

public struct PublicRepositoryReadPageResult: Sendable, Equatable {
    public let did: String
    public let state: PublicRepositoryState
    public let page: PublicRepositoryReadPage

    public init(
        did: String,
        state: PublicRepositoryState,
        page: PublicRepositoryReadPage
    ) throws {
        guard AccountControlIdentifiers.isDID(did), state.did == did else {
            throw PublicRepositoryReadError.unavailable
        }
        self.did = did
        self.state = state
        self.page = page
    }
}

/// Process-wide and per-account admission for disk-backed CAR spools and
/// descriptor-backed response bodies. Each request reserves its worst-case
/// size before creating a file or opening/verifying a blob descriptor,
/// bounding both disk amplification and the number of slow consumers.
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
    private let maximumGlobalLeases: Int
    private let maximumPerAccountLeases: Int
    private let lock = NSLock()
    private var leases: [UUID: (account: String, bytes: Int)] = [:]
    private var reservedByAccount: [String: Int] = [:]

    public init(
        maximumGlobalBytes: Int = 1_024 * 1_024 * 1_024,
        maximumPerAccountBytes: Int = 512 * 1_024 * 1_024,
        maximumGlobalLeases: Int = 64,
        maximumPerAccountLeases: Int = 16
    ) throws {
        guard maximumGlobalBytes > 0,
              maximumPerAccountBytes > 0,
              maximumPerAccountBytes <= maximumGlobalBytes,
              maximumGlobalLeases > 0,
              maximumPerAccountLeases > 0,
              maximumPerAccountLeases <= maximumGlobalLeases else {
            throw PublicRepositoryReadError.unavailable
        }
        self.maximumGlobalBytes = maximumGlobalBytes
        self.maximumPerAccountBytes = maximumPerAccountBytes
        self.maximumGlobalLeases = maximumGlobalLeases
        self.maximumPerAccountLeases = maximumPerAccountLeases
    }

    /// Shared fallback for HTTP servers that are assembled outside the
    /// preopened SQLite directory. Production `serve` passes the directory's
    /// admission explicitly; the fallback still keeps standalone/test
    /// servers bounded instead of silently accepting unlimited streams.
    public static let shared: PublicRepositorySpoolAdmission = {
        do {
            return try PublicRepositorySpoolAdmission()
        } catch {
            preconditionFailure("default public transfer admission is invalid")
        }
    }()

    public func reserve(
        accountDID: String,
        maximumBytes: Int
    ) -> PublicRepositorySpoolLease? {
        guard AccountControlIdentifiers.isDID(accountDID),
              maximumBytes > 0 else { return nil }
        return lock.withLock {
            let global = leases.values.reduce(0) { partial, lease in
                let (next, overflow) = partial.addingReportingOverflow(lease.bytes)
                return overflow ? Int.max : next
            }
            let account = reservedByAccount[accountDID, default: 0]
            let accountLeaseCount = leases.values.reduce(into: 0) { count, lease in
                if lease.account == accountDID { count += 1 }
            }
            guard leases.count < maximumGlobalLeases,
                  accountLeaseCount < maximumPerAccountLeases,
                  global <= maximumGlobalBytes,
                  account <= maximumPerAccountBytes,
                  maximumBytes <= maximumGlobalBytes - global,
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
        let bodyByteCount = try spoolByteCount(fileDescriptor: handle.fileDescriptor)
        var streamedByteCount = 0
        var reusableChunk = Data(count: maximumChunkBytes)
        while streamedByteCount < bodyByteCount {
            try Task.checkCancellation()
            let requestedByteCount = min(
                maximumChunkBytes,
                bodyByteCount - streamedByteCount
            )
            let chunkByteCount = try readPOSIXBytes(
                fileDescriptor: handle.fileDescriptor,
                offset: streamedByteCount,
                maximumBytes: requestedByteCount,
                into: &reusableChunk
            )
            guard chunkByteCount > 0 else {
                throw PublicRepositoryReadError.unavailable
            }
            let (nextByteCount, overflow) = streamedByteCount
                .addingReportingOverflow(chunkByteCount)
            guard !overflow, nextByteCount <= bodyByteCount else {
                throw PublicRepositoryReadError.unavailable
            }
            streamedByteCount = nextByteCount
            if chunkByteCount == reusableChunk.count {
                try await consume(reusableChunk)
            } else {
                try await consume(Data(reusableChunk.prefix(chunkByteCount)))
            }
        }
        var endProbe = Data(count: 1)
        guard try readPOSIXBytes(
            fileDescriptor: handle.fileDescriptor,
            offset: streamedByteCount,
            maximumBytes: 1,
            into: &endProbe
        ) == 0 else {
            throw PublicRepositoryReadError.unavailable
        }
    }

    /// Read into a fixed allocation rather than using Foundation's
    /// `read(upToCount:)`, whose bridged autoreleased reads can accumulate
    /// across an async response drain. The initial byte count and terminal
    /// probe make both truncation and descriptor growth fail closed.
    private func readPOSIXBytes(
        fileDescriptor: Int32,
        offset: Int,
        maximumBytes: Int,
        into buffer: inout Data
    ) throws -> Int {
        guard fileDescriptor >= 0,
              offset >= 0,
              maximumBytes > 0,
              maximumBytes <= buffer.count else {
            throw PublicRepositoryReadError.unavailable
        }
        return try buffer.withUnsafeMutableBytes { bytes in
            guard let baseAddress = bytes.baseAddress else { return 0 }
            while true {
                #if canImport(Darwin)
                let result = Darwin.pread(
                    fileDescriptor, baseAddress, maximumBytes, off_t(offset)
                )
                #elseif canImport(Glibc)
                let result = Glibc.pread(
                    fileDescriptor, baseAddress, maximumBytes, off_t(offset)
                )
                #else
                let result = -1
                #endif
                if result >= 0 { return result }
                guard errno == EINTR else {
                    throw PublicRepositoryReadError.unavailable
                }
            }
        }
    }

    private func spoolByteCount(fileDescriptor: Int32) throws -> Int {
        guard fileDescriptor >= 0 else { throw PublicRepositoryReadError.unavailable }
        #if canImport(Darwin)
        var status = Darwin.stat()
        let result = Darwin.fstat(fileDescriptor, &status)
        #elseif canImport(Glibc)
        var status = Glibc.stat()
        let result = Glibc.fstat(fileDescriptor, &status)
        #else
        let result = -1
        #endif
        guard result == 0,
              status.st_size >= 0,
              status.st_size <= off_t(Int.max) else {
            throw PublicRepositoryReadError.unavailable
        }
        return Int(status.st_size)
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

    func publicRepositoryDescriptionOutcome(
        selector: String
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadDescription>
    func publicRepositoryRecordOutcome(
        selector: String,
        path: PublicRepositoryPath,
        expectedCID: CID?
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadRecordResult>
    func publicRepositoryRecordsOutcome(
        selector: String,
        collection: String,
        limit: Int,
        cursor: String?,
        reverse: Bool
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadPageResult>
    func publicRepositoryCAROutcome(
        selector: String
    ) async throws -> PublicRepositoryReadOutcome<PublicRepositoryReadCAR>
}
