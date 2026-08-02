import Crypto
import Foundation
import Petrel
import SwanSpaces

/// The authenticated action represented by one value-bearing `listRepoOps`
/// entry. It is deliberately explicit even though the wire format encodes the
/// action through nullable CID fields.
public enum PermissionedRemoteReplicaIncrementalAction:
    String, Sendable, Equatable, Hashable
{
    case create
    case update
    case delete
}

/// One operation whose context signature, content binding, and source identity
/// have already been verified by the network layer. Storage still validates
/// every record and transition invariant before changing durable state.
public struct VerifiedPermissionedRemoteReplicaOperation:
    Sendable, Equatable
{
    public let operationIndex: Int
    public let wireRevision: TID
    public let action: PermissionedRemoteReplicaIncrementalAction
    public let uri: SpaceRecordURI
    public let cid: CID?
    public let previousCID: CID?
    public let value: Data?

    public init(
        operationIndex: Int,
        wireRevision: TID,
        action: PermissionedRemoteReplicaIncrementalAction,
        uri: SpaceRecordURI,
        cid: CID?,
        previousCID: CID?,
        value: Data?
    ) {
        self.operationIndex = operationIndex
        self.wireRevision = wireRevision
        self.action = action
        self.uri = uri
        self.cid = cid
        self.previousCID = previousCID
        self.value = value
    }
}

/// The terminal authenticated repository facts for one complete wire-revision
/// batch. `ltHash` is supplied separately from its commitment so SQLite can
/// compare the fully reconstructed state, rather than accepting a commitment
/// alone as a substitute for state validation.
public struct PermissionedRemoteReplicaIncrementalTerminalHead:
    Sendable, Equatable
{
    public let wireRevision: TID
    public let ltHash: Data
    public let commitment: Data
    public let recordCount: Int
    public let operationCount: Int
    public let operationDigest: Data

    public init(
        wireRevision: TID,
        ltHash: Data,
        commitment: Data,
        recordCount: Int,
        operationCount: Int,
        operationDigest: Data
    ) throws {
        guard ltHash.count == LtHash.byteCount,
              commitment.count == 32,
              (0 ... SpaceCARRecoveryLimits.absoluteMaximumIndexEntries)
                .contains(recordCount),
              (1 ... SpaceWriteLimits.maximumOperations)
                .contains(operationCount),
              operationDigest.count == 32 else {
            throw PermissionedRemoteReplicaIncrementalInputError
                .invalidTerminalHead
        }
        self.wireRevision = wireRevision
        self.ltHash = ltHash
        self.commitment = commitment
        self.recordCount = recordCount
        self.operationCount = operationCount
        self.operationDigest = operationDigest
    }
}

/// Ordered witness produced by the authenticated incremental verifier after it
/// has established that the terminal response contains one complete batch.
public enum PermissionedRemoteReplicaIncrementalOperationWitness {
    public static func digest(
        _ operations: [VerifiedPermissionedRemoteReplicaOperation]
    ) -> Data {
        var hasher = SHA256()
        hasher.update(data: Data(
            "swan.permissioned.remote-replica.incremental.operations.v1".utf8
        ))
        func append(_ value: Data) {
            var length = UInt64(value.count).bigEndian
            withUnsafeBytes(of: &length) {
                hasher.update(data: Data($0))
            }
            hasher.update(data: value)
        }
        append(Data(String(operations.count).utf8))
        for operation in operations {
            append(Data(String(operation.operationIndex).utf8))
            append(Data(operation.wireRevision.toString().utf8))
            append(Data(operation.action.rawValue.utf8))
            append(Data(operation.uri.rawValue.utf8))
            append(operation.cid.map { Data($0.string.utf8) } ?? Data())
            append(operation.previousCID.map {
                Data($0.string.utf8)
            } ?? Data())
            append(operation.value ?? Data())
        }
        return Data(hasher.finalize())
    }
}

public enum PermissionedRemoteReplicaIncrementalInputError:
    Error, Sendable, Equatable
{
    case invalidRequestIdentity
    case invalidTarget
    case invalidOperationBudget
    case invalidTerminalHead
}

/// A complete, nonempty terminal-revision batch. The caller's digest is a
/// replay identity; SQLite additionally computes and persists its own digest
/// over every semantic field so a caller cannot reuse the ID or digest for a
/// differently shaped batch.
public struct PermissionedRemoteReplicaIncrementalBatch:
    Sendable, Equatable
{
    public let target: PermissionedRemoteReplicaTarget
    public let expectedHead: PermissionedRemoteReplicaHead
    public let terminalHead: PermissionedRemoteReplicaIncrementalTerminalHead
    public let operations: [VerifiedPermissionedRemoteReplicaOperation]
    public let requestID: String
    public let requestSequence: UInt64
    public let requestDigest: Data

    public init(
        target: PermissionedRemoteReplicaTarget,
        expectedHead: PermissionedRemoteReplicaHead,
        terminalHead: PermissionedRemoteReplicaIncrementalTerminalHead,
        operations: [VerifiedPermissionedRemoteReplicaOperation],
        requestID: String,
        requestSequence: UInt64,
        requestDigest: Data
    ) throws {
        guard target == expectedHead.target else {
            throw PermissionedRemoteReplicaIncrementalInputError.invalidTarget
        }
        guard !requestID.isEmpty, requestID.utf8.count <= 512,
              requestSequence > 0,
              !requestID.contains("\0"), requestDigest.count == 32 else {
            throw PermissionedRemoteReplicaIncrementalInputError
                .invalidRequestIdentity
        }
        guard (1 ... SpaceWriteLimits.maximumOperations)
                .contains(operations.count) else {
            throw PermissionedRemoteReplicaIncrementalInputError
                .invalidOperationBudget
        }
        var valueBytes = 0
        for (expectedIndex, operation) in operations.enumerated() {
            guard operation.operationIndex == expectedIndex else {
                throw PermissionedRemoteReplicaIncrementalInputError
                    .invalidOperationBudget
            }
            let count = operation.value?.count ?? 0
            do {
                valueBytes = try SpaceWriteLimits.addingValueBytes(
                    valueBytes,
                    count
                )
            } catch {
                throw PermissionedRemoteReplicaIncrementalInputError
                    .invalidOperationBudget
            }
        }
        guard terminalHead.operationCount == operations.count,
              terminalHead.operationDigest
                == PermissionedRemoteReplicaIncrementalOperationWitness
                    .digest(operations) else {
            throw PermissionedRemoteReplicaIncrementalInputError
                .invalidTerminalHead
        }
        let canonicalDigest = Self.canonicalDigest(
            target: target,
            expectedHead: expectedHead,
            terminalHead: terminalHead,
            operations: operations,
            requestSequence: requestSequence
        )
        guard requestDigest == canonicalDigest else {
            throw PermissionedRemoteReplicaIncrementalInputError
                .invalidRequestIdentity
        }
        self.target = target
        self.expectedHead = expectedHead
        self.terminalHead = terminalHead
        self.operations = operations
        self.requestID = requestID
        self.requestSequence = requestSequence
        self.requestDigest = requestDigest
    }

    /// Canonical witness for the complete verified batch. The network verifier
    /// computes this only after it has authenticated the terminal response and
    /// established that the returned operation page is complete. Recomputing
    /// it in storage prevents a same-TID omission or reorder from being hidden
    /// behind an unchanged terminal commitment.
    public static func canonicalDigest(
        target: PermissionedRemoteReplicaTarget,
        expectedHead: PermissionedRemoteReplicaHead,
        terminalHead: PermissionedRemoteReplicaIncrementalTerminalHead,
        operations: [VerifiedPermissionedRemoteReplicaOperation],
        requestSequence: UInt64
    ) -> Data {
        var hasher = SHA256()
        hasher.update(data: Data(
            "swan.permissioned.remote-replica.incremental.batch.v2".utf8
        ))
        func append(_ value: Data) {
            var length = UInt64(value.count).bigEndian
            withUnsafeBytes(of: &length) {
                hasher.update(data: Data($0))
            }
            hasher.update(data: value)
        }
        append(Data(target.receiverDID.utf8))
        append(Data(target.space.rawValue.utf8))
        append(Data(target.repositoryDID.utf8))
        var fixedRequestSequence = requestSequence.bigEndian
        withUnsafeBytes(of: &fixedRequestSequence) {
            append(Data($0))
        }
        append(Data(String(expectedHead.generation).utf8))
        append(Data(expectedHead.wireRevision.toString().utf8))
        append(Data(expectedHead.historyFloorWireRevision.toString().utf8))
        append(expectedHead.ltHash)
        append(expectedHead.commitment)
        append(expectedHead.stateMarker)
        append(Data(terminalHead.wireRevision.toString().utf8))
        append(terminalHead.ltHash)
        append(terminalHead.commitment)
        append(Data(String(terminalHead.recordCount).utf8))
        append(Data(String(terminalHead.operationCount).utf8))
        append(terminalHead.operationDigest)
        append(Data(String(operations.count).utf8))
        for operation in operations {
            append(Data(String(operation.operationIndex).utf8))
            append(Data(operation.wireRevision.toString().utf8))
            append(Data(operation.action.rawValue.utf8))
            append(Data(operation.uri.rawValue.utf8))
            append(operation.cid.map { Data($0.string.utf8) } ?? Data())
            append(operation.previousCID.map {
                Data($0.string.utf8)
            } ?? Data())
            append(operation.value ?? Data())
        }
        return Data(hasher.finalize())
    }
}

/// The durable result records the unchanged full-CAR snapshot generation.
/// Incremental application advances its revision/state inside that generation;
/// it does not claim that a replacement CAR was installed.
public struct AppliedPermissionedRemoteReplicaIncrementalBatch:
    Sendable, Equatable
{
    public let requestID: String
    public let requestSequence: UInt64
    public let requestDigest: Data
    public let head: PermissionedRemoteReplicaHead
    public let recordCount: Int
    public let appliedAt: Int64

    public init(
        requestID: String,
        requestSequence: UInt64,
        requestDigest: Data,
        head: PermissionedRemoteReplicaHead,
        recordCount: Int,
        appliedAt: Int64
    ) {
        self.requestID = requestID
        self.requestSequence = requestSequence
        self.requestDigest = requestDigest
        self.head = head
        self.recordCount = recordCount
        self.appliedAt = appliedAt
    }
}

public enum PermissionedRemoteReplicaIncrementalApplyOutcome:
    Sendable, Equatable
{
    case applied(AppliedPermissionedRemoteReplicaIncrementalBatch)
    case exactDuplicate(AppliedPermissionedRemoteReplicaIncrementalBatch)
    case casConflict
    case conflictingReplay
    case staleOrReordered
    case integrityFailure
    case fullCARRecoveryRequired
}

/// One transactionally consistent starting point for network verification.
/// The record count is needed to authenticate create/delete deltas without
/// enumerating the receiver's private repository into the network layer.
public struct PermissionedRemoteReplicaIncrementalBaseState:
    Sendable, Equatable
{
    public let head: PermissionedRemoteReplicaHead
    public let recordCount: Int

    public init(head: PermissionedRemoteReplicaHead, recordCount: Int) throws {
        guard (0 ... SpaceCARRecoveryLimits.absoluteMaximumIndexEntries)
            .contains(recordCount) else {
            throw PermissionedRemoteReplicaIncrementalInputError
                .invalidTerminalHead
        }
        self.head = head
        self.recordCount = recordCount
    }
}

/// Network-free durable boundary. Callers pass verified facts, never a generic
/// authentication Boolean; all state transitions and replay decisions occur in
/// one SQLite transaction.
public protocol PermissionedRemoteReplicaIncrementalStore: Sendable {
    func permissionedRemoteReplicaIncrementalBaseState(
        target: PermissionedRemoteReplicaTarget
    ) async throws -> PermissionedRemoteReplicaIncrementalBaseState?

    func applyVerifiedPermissionedRemoteReplicaBatch(
        _ batch: PermissionedRemoteReplicaIncrementalBatch,
        appliedAt: Int64
    ) async throws -> PermissionedRemoteReplicaIncrementalApplyOutcome
}
