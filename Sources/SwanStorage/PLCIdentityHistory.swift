import Foundation
import Petrel
import SwanCore

/// One authenticated PLC operation retained beside the account's public
/// repository. The operation body is canonical JSON from the PLC client; it
/// is not an arbitrary document accepted by a request handler. Private key
/// material and control-plane credentials are deliberately absent.
public struct PublicPLCOperationHistoryEntry: Sendable, Equatable {
    public let cid: String
    public let previousCID: String?
    public let canonicalJSON: Data
    public let createdAt: Date
    public let signingKeyGeneration: UInt64
    public let rotationKeyGeneration: UInt64

    public init(
        cid: String,
        previousCID: String?,
        canonicalJSON: Data,
        createdAt: Date,
        signingKeyGeneration: UInt64,
        rotationKeyGeneration: UInt64
    ) throws {
        guard !cid.isEmpty, cid.utf8.count <= 256,
              previousCID.map({ !$0.isEmpty && $0.utf8.count <= 256 }) ?? true,
              !canonicalJSON.isEmpty, canonicalJSON.count <= 32 * 1_024,
              createdAt.timeIntervalSince1970.isFinite,
              createdAt.timeIntervalSince1970 >= 0,
              signingKeyGeneration > 0,
              signingKeyGeneration == rotationKeyGeneration,
              (try? CID.parse(cid)) != nil,
              previousCID == nil || (try? CID.parse(previousCID!)) != nil else {
            throw SwanError.malformed("PLC operation history entry is invalid")
        }
        self.cid = cid
        self.previousCID = previousCID
        self.canonicalJSON = canonicalJSON
        self.createdAt = createdAt
        self.signingKeyGeneration = signingKeyGeneration
        self.rotationKeyGeneration = rotationKeyGeneration
    }
}

/// The authenticated terminal identity used by public `describeRepo`.
/// `genesisOperationCID` remains stable across rotation while
/// `terminalOperationCID` identifies the current PLC document state.
public struct PublicPLCIdentityState: Sendable, Equatable {
    public let genesisOperationCID: String
    public let terminalOperationCID: String
    public let canonicalHandle: String
    public let pdsOrigin: String
    public let signingDIDKey: String
    public let rotationDIDKey: String
    public let keyGeneration: UInt64

    public init(
        genesisOperationCID: String,
        terminalOperationCID: String,
        canonicalHandle: String,
        pdsOrigin: String,
        signingDIDKey: String,
        rotationDIDKey: String,
        keyGeneration: UInt64
    ) throws {
        guard (try? CID.parse(genesisOperationCID)) != nil,
              (try? CID.parse(terminalOperationCID)) != nil,
              !canonicalHandle.isEmpty,
              !pdsOrigin.isEmpty,
              signingDIDKey.hasPrefix("did:key:z"),
              rotationDIDKey.hasPrefix("did:key:z"),
              keyGeneration > 0 else {
            throw SwanError.malformed("PLC identity state is invalid")
        }
        self.genesisOperationCID = genesisOperationCID
        self.terminalOperationCID = terminalOperationCID
        self.canonicalHandle = canonicalHandle
        self.pdsOrigin = pdsOrigin
        self.signingDIDKey = signingDIDKey
        self.rotationDIDKey = rotationDIDKey
        self.keyGeneration = keyGeneration
    }
}

/// Per-account durable PLC history. Implementations must make insertion
/// idempotent by CID and reject a conflicting body for an existing CID.
public protocol PublicPLCIdentityHistoryStore: Sendable {
    func installPublicPLCOperation(
        _ entry: PublicPLCOperationHistoryEntry
    ) async throws -> PublicPLCOperationHistoryEntry

    func publicPLCOperationHistory() async throws
        -> [PublicPLCOperationHistoryEntry]
}

/// The crypto implementation lives in SwanAccounts, while SQLite and public
/// repository adapters depend only on this narrow storage protocol.
public protocol PublicPLCIdentityVerifying: PublicPLCGenesisVerifying {
    func verifyIdentityHistory(
        _ history: [PublicPLCOperationHistoryEntry],
        expectedDID: String
    ) throws -> PublicPLCIdentityState
}
