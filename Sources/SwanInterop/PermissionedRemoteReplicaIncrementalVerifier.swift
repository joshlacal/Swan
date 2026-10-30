import Foundation
import Petrel
import PetrelCrypto
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanStorage

public enum PermissionedRemoteReplicaIncrementalVerificationError:
    Error, Sendable, Equatable
{
    case emptyOperations
    case operationLimitExceeded
    case invalidRevisionOrder
    case invalidOperation
    case missingValue
    case valueCIDMismatch
    case invalidCommit
    case commitmentMismatch
    case contentBindingMismatch
    case contextSignatureMismatch
    case mixedHead
}

public struct VerifiedPermissionedRemoteReplicaIncrementalPage:
    Sendable, Equatable
{
    public let operations: [VerifiedPermissionedRemoteReplicaOperation]
    public let terminalHead: PermissionedRemoteReplicaIncrementalTerminalHead
    public let freshnessWitness: PermissionedRemoteReplicaFreshnessWitness

    public init(
        operations: [VerifiedPermissionedRemoteReplicaOperation],
        terminalHead: PermissionedRemoteReplicaIncrementalTerminalHead,
        freshnessWitness: PermissionedRemoteReplicaFreshnessWitness
    ) {
        self.operations = operations
        self.terminalHead = terminalHead
        self.freshnessWitness = freshnessWitness
    }
}

/// Converts a complete value-bearing `listRepoOps` interval into the exact
/// verified facts accepted by the durable incremental store. Network I/O and
/// persistence remain outside this component.
public enum PermissionedRemoteReplicaIncrementalVerifier {
    public static func verify(
        operations wireOperations: [ComAtprotoSpaceListRepoOps.OpEntry],
        commit: ComAtprotoSpaceDefs.Commit,
        base: PermissionedRemoteReplicaIncrementalBaseState,
        target: PermissionedRemoteReplicaTarget,
        sharedSecret: Data,
        mac: Data
    ) throws -> VerifiedPermissionedRemoteReplicaIncrementalPage {
        guard base.head.target == target else {
            throw PermissionedRemoteReplicaIncrementalVerificationError
                .invalidOperation
        }
        guard !wireOperations.isEmpty else {
            throw PermissionedRemoteReplicaIncrementalVerificationError
                .emptyOperations
        }
        guard wireOperations.count <= SpaceWriteLimits.maximumOperations else {
            throw PermissionedRemoteReplicaIncrementalVerificationError
                .operationLimitExceeded
        }

        var ltHash: LtHash
        do {
            ltHash = try LtHash(serialized: base.head.ltHash)
        } catch {
            throw PermissionedRemoteReplicaIncrementalVerificationError
                .commitmentMismatch
        }
        var recordCount = base.recordCount
        var previousRevision = base.head.wireRevision
        var operations: [VerifiedPermissionedRemoteReplicaOperation] = []
        operations.reserveCapacity(wireOperations.count)

        for (index, entry) in wireOperations.enumerated() {
            // The generated wire type now carries a parsed TID directly.
            let revision: TID = entry.rev
            guard revision > base.head.wireRevision,
                  revision >= previousRevision else {
                throw PermissionedRemoteReplicaIncrementalVerificationError
                    .invalidRevisionOrder
            }
            previousRevision = revision

            let uri: SpaceRecordURI
            do {
                uri = try SpaceRecordURI(
                    space: target.space,
                    author: target.repositoryDID,
                    collection: entry.collection.nsidString(),
                    rkey: entry.rkey.value
                )
            } catch {
                throw PermissionedRemoteReplicaIncrementalVerificationError
                    .invalidOperation
            }

            let action: PermissionedRemoteReplicaIncrementalAction
            let value: Data?
            switch (entry.cid, entry.prev) {
            case let (.some(cid), nil):
                action = .create
                value = try canonicalValue(entry.value, cid: cid)
                recordCount += 1
                ltHash.add(element: element(uri: uri, cid: cid.string))
            case let (.some(cid), .some(previous)):
                action = .update
                value = try canonicalValue(entry.value, cid: cid)
                ltHash.remove(element: element(uri: uri, cid: previous.string))
                ltHash.add(element: element(uri: uri, cid: cid.string))
            case let (nil, .some(previous)):
                guard entry.value == nil else {
                    throw PermissionedRemoteReplicaIncrementalVerificationError
                        .invalidOperation
                }
                action = .delete
                value = nil
                recordCount -= 1
                ltHash.remove(element: element(uri: uri, cid: previous.string))
            case (nil, nil):
                throw PermissionedRemoteReplicaIncrementalVerificationError
                    .invalidOperation
            }
            guard (0 ... SpaceCARRecoveryLimits.absoluteMaximumIndexEntries)
                .contains(recordCount) else {
                throw PermissionedRemoteReplicaIncrementalVerificationError
                    .invalidOperation
            }
            operations.append(.init(
                operationIndex: index,
                wireRevision: revision,
                action: action,
                uri: uri,
                cid: entry.cid,
                previousCID: entry.prev,
                value: value
            ))
        }

        let freshness = try verifyCommit(
            commit,
            target: target,
            sharedSecret: sharedSecret,
            mac: mac
        )
        guard freshness.wireRevision == previousRevision else {
            throw PermissionedRemoteReplicaIncrementalVerificationError
                .invalidCommit
        }
        guard ltHash.commitment == freshness.commitment else {
            throw PermissionedRemoteReplicaIncrementalVerificationError
                .commitmentMismatch
        }
        let terminal = try PermissionedRemoteReplicaIncrementalTerminalHead(
            wireRevision: freshness.wireRevision,
            ltHash: ltHash.serialized,
            commitment: freshness.commitment,
            recordCount: recordCount,
            operationCount: operations.count,
            operationDigest:
                PermissionedRemoteReplicaIncrementalOperationWitness
                    .digest(operations)
        )
        return .init(
            operations: operations,
            terminalHead: terminal,
            freshnessWitness: freshness
        )
    }

    public static func verifyCommit(
        _ commit: ComAtprotoSpaceDefs.Commit,
        target: PermissionedRemoteReplicaTarget,
        sharedSecret: Data,
        mac: Data
    ) throws -> PermissionedRemoteReplicaFreshnessWitness {
        let value: SpaceRepositoryCommit
        do {
            value = try SpaceRepositoryCommit(
                ver: commit.ver, repo: commit.repo.didString(),
                space: SpaceURI(commit.space.uriString()), rev: commit.rev.toString(), data: commit.data.data
            )
        } catch { throw PermissionedRemoteReplicaIncrementalVerificationError.invalidCommit }
        guard value.repo == target.repositoryDID, value.space == target.space else {
            throw PermissionedRemoteReplicaIncrementalVerificationError.invalidCommit
        }
        do {
            try SpaceMAC.verify(mac: mac, expected: value.mac(sharedSecret: sharedSecret))
        } catch { throw PermissionedRemoteReplicaIncrementalVerificationError.contentBindingMismatch }
        return try PermissionedRemoteReplicaFreshnessWitness(wireRevision: commit.rev, commitment: value.data)
    }

    public static func requireSameHead(
        _ page: PermissionedRemoteReplicaFreshnessWitness,
        _ latest: PermissionedRemoteReplicaFreshnessWitness
    ) throws {
        guard page == latest else {
            throw PermissionedRemoteReplicaIncrementalVerificationError
                .mixedHead
        }
    }

    static func canonicalValue(
        _ value: ATProtocolValueContainer?,
        cid: CID
    ) throws -> Data {
        guard let value else {
            throw PermissionedRemoteReplicaIncrementalVerificationError
                .missingValue
        }
        let cborValue = try value.toCBORValue()
        guard cborValue is OrderedCBORMap || cborValue is [String: Any] else {
            throw PermissionedRemoteReplicaIncrementalVerificationError
                .invalidOperation
        }
        let bytes = try DAGCBOR.encodeValue(cborValue)
        _ = try CARRepository.decodeRecordCBOR(bytes)
        guard CID.fromDAGCBOR(bytes) == cid else {
            throw PermissionedRemoteReplicaIncrementalVerificationError
                .valueCIDMismatch
        }
        return bytes
    }

    private static func element(uri: SpaceRecordURI, cid: String) -> String {
        "\(uri.collection)/\(uri.rkey)/\(cid)"
    }
}
