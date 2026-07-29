import Petrel
import SwanCore
import SwanPublicRepository

/// The durable trust anchor retained after Swan authenticates a PLC document
/// and its complete audit. Only the issuer and terminal operation CID are
/// persisted; verification methods and audit bodies remain owned by the PLC
/// client and are never copied into `control.sqlite`.
public struct PLCCredentialKeyContinuityCheckpoint: Sendable, Equatable {
    public let issuer: String
    public let terminalCID: String

    public init(issuer: String, terminalCID: String) throws {
        guard Self.isPLCIssuer(issuer),
              Self.isCanonicalPLCOperationCID(terminalCID) else {
            throw PLCCredentialKeyContinuityStoreError.invalidInput
        }
        self.issuer = issuer
        self.terminalCID = terminalCID
    }

    fileprivate static func isPLCIssuer(_ issuer: String) -> Bool {
        issuer.hasPrefix("did:plc:") && AccountControlIdentifiers.isDID(issuer)
    }

    fileprivate static func isCanonicalPLCOperationCID(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 256,
              let cid = try? CID.parse(value),
              cid.string == value,
              (try? PublicRepositoryCID.validate(cid)) != nil else {
            return false
        }
        return true
    }
}

/// The complete bounded set of durable PLC credential-key trust anchors
/// included only in an authenticated operator backup.
///
/// Ordering is canonical by issuer. Each issuer occurs exactly once, and only
/// the terminal CID is carried: audit bodies, service URLs, verification
/// methods, and key material are deliberately outside this format.
public struct PLCCredentialKeyContinuityInventory: Sendable, Equatable {
    public static let maximumCheckpointCount = 1_024
    public static let maximumCheckpointBytes = 256 * 1_024

    public let checkpoints: [PLCCredentialKeyContinuityCheckpoint]

    public init(
        checkpoints: [PLCCredentialKeyContinuityCheckpoint]
    ) throws {
        guard checkpoints.count <= Self.maximumCheckpointCount else {
            throw PLCCredentialKeyContinuityStoreError.invalidInput
        }
        let canonical = checkpoints.sorted { lhs, rhs in
            lhs.issuer.utf8.lexicographicallyPrecedes(rhs.issuer.utf8)
        }
        var previousIssuer: String?
        var totalBytes = 0
        for checkpoint in canonical {
            let byteCount =
                checkpoint.issuer.utf8.count + checkpoint.terminalCID.utf8.count
            guard previousIssuer != checkpoint.issuer,
                  totalBytes <= Self.maximumCheckpointBytes - byteCount else {
                throw PLCCredentialKeyContinuityStoreError.invalidInput
            }
            previousIssuer = checkpoint.issuer
            totalBytes += byteCount
        }
        self.checkpoints = canonical
    }
}

/// A bounded, already-verified PLC audit proposed as the next durable
/// credential-key continuity checkpoint. The store compares the existing
/// terminal CID against this audit atomically; callers cannot advance a
/// checkpoint with an unrelated historical prefix or fork.
public struct PLCCredentialKeyContinuityAdvance: Sendable, Equatable {
    public static let maximumAuditCIDCount = 1_024
    public static let maximumAuditCIDBytes = 256 * 1_024

    public let checkpoint: PLCCredentialKeyContinuityCheckpoint
    public let auditCIDs: [String]

    public init(
        issuer: String,
        terminalCID: String,
        auditCIDs: [String]
    ) throws {
        let checkpoint = try PLCCredentialKeyContinuityCheckpoint(
            issuer: issuer,
            terminalCID: terminalCID
        )
        guard !auditCIDs.isEmpty,
              auditCIDs.count <= Self.maximumAuditCIDCount,
              auditCIDs.last == terminalCID else {
            throw PLCCredentialKeyContinuityStoreError.invalidInput
        }
        var seen = Set<String>()
        var totalBytes = 0
        for cid in auditCIDs {
            let byteCount = cid.utf8.count
            guard byteCount <= 256,
                  totalBytes <= Self.maximumAuditCIDBytes - byteCount,
                  PLCCredentialKeyContinuityCheckpoint
                    .isCanonicalPLCOperationCID(cid),
                  seen.insert(cid).inserted else {
                throw PLCCredentialKeyContinuityStoreError.invalidInput
            }
            totalBytes += byteCount
        }
        self.checkpoint = checkpoint
        self.auditCIDs = auditCIDs
    }
}

public enum PLCCredentialKeyContinuityStoreError:
    Error, Sendable, Equatable
{
    case invalidInput
    case continuityViolation
    case malformedRecord
}

/// Durable compare-and-advance storage for remote PLC credential-key trust.
/// Implementations must serialize the read/continuity-check/write sequence
/// across independently opened processes. Network I/O and audit verification
/// happen before this boundary.
public protocol PLCCredentialKeyContinuityStore: Sendable {
    func advancePLCCredentialKeyContinuity(
        _ advance: PLCCredentialKeyContinuityAdvance
    ) async throws -> PLCCredentialKeyContinuityCheckpoint

    func plcCredentialKeyContinuityCheckpoint(
        for issuer: String
    ) async throws -> PLCCredentialKeyContinuityCheckpoint?
}
