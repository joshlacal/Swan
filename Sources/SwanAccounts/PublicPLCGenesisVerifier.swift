import Foundation
import SwanCore
import SwanStorage

public struct SwanPublicPLCGenesisVerifier: PublicPLCGenesisVerifying {
    public init() {}

    public func verifyGenesis(
        facts: PublicPLCGenesisFacts,
        expectedDID: String
    ) throws -> String {
        let operation = try PLCOperationCodec.reconstructGenesis(
            signingDIDKey: facts.signingDIDKey,
            rotationDIDKey: facts.rotationDIDKey,
            canonicalHandle: facts.canonicalHandle,
            pdsOrigin: facts.pdsOrigin,
            signature: facts.signature
        )
        try PLCOperationCodec.verifyGenesis(operation, expectedDID: expectedDID)
        return try operation.cid.string
    }
}

extension SwanPublicPLCGenesisVerifier: PublicPLCIdentityVerifying {
    public func verifyIdentityHistory(
        _ history: [PublicPLCOperationHistoryEntry],
        expectedDID: String
    ) throws -> PublicPLCIdentityState {
        guard !history.isEmpty else {
            throw SwanError.unavailable("PLC identity history is empty")
        }
        try PLCOperationCodec.validateCanonicalDID(expectedDID)

        var previousDate: Date?
        var previousOperation: PLCSignedOperation?
        var previousCID: String?

        for (index, entry) in history.enumerated() {
            guard previousDate.map({ entry.createdAt >= $0 }) ?? true else {
                throw SwanError.unauthorized("PLC identity history is out of order")
            }
            let canonicalOperation = try PLCOperationCodec.decodeSignedJSON(
                entry.canonicalJSON
            )
            let canonicalJSON = try canonicalOperation.canonicalJSON
            guard entry.canonicalJSON == canonicalJSON else {
                throw SwanError.unauthorized("PLC operation is not canonical")
            }
            let operation = canonicalOperation
            guard try operation.cid.string == entry.cid,
                  operation.prev == entry.previousCID else {
                throw SwanError.unauthorized("PLC operation history CID binding is invalid")
            }
            guard let regular = operation.regular else {
                throw SwanError.unauthorized("PLC tombstone cannot serve a public repository")
            }

            if index == 0 {
                guard entry.previousCID == nil,
                      entry.signingKeyGeneration == 1,
                      entry.rotationKeyGeneration == 1 else {
                    throw SwanError.unauthorized("PLC genesis history entry is invalid")
                }
                try PLCOperationCodec.verifyGenesis(operation, expectedDID: expectedDID)
            } else {
                guard let previousOperation,
                      let previousCID,
                      entry.previousCID == previousCID,
                      entry.signingKeyGeneration == entry.rotationKeyGeneration,
                      history[index - 1].signingKeyGeneration < UInt64.max,
                      entry.signingKeyGeneration
                        == history[index - 1].signingKeyGeneration + 1 else {
                    throw SwanError.unauthorized("PLC rotation generation is invalid")
                }
                guard let parent = previousOperation.regular else {
                    throw SwanError.unauthorized("PLC rotation parent is invalid")
                }
                _ = try PLCOperationCodec.verify(
                    operation,
                    authorizedRotationKeys: parent.rotationKeys
                )
            }

            guard regular.verificationMethods.count == 1,
                  regular.verificationMethods["atproto"].map(PLCDIDKeyCodec.isCanonical) == true,
                  regular.rotationKeys.count >= 1,
                  regular.rotationKeys.allSatisfy({ PLCDIDKeyCodec.isCanonical($0) }) else {
                throw SwanError.unauthorized("PLC operation identity keys are invalid")
            }
            previousDate = entry.createdAt
            previousCID = entry.cid
            previousOperation = operation
        }

        guard let terminal = previousOperation?.regular,
              let terminalCID = previousCID,
              let signingDIDKey = terminal.verificationMethods["atproto"],
              let rotationDIDKey = terminal.rotationKeys.first,
              terminal.alsoKnownAs.count == 1,
              let alias = terminal.alsoKnownAs.first,
              alias.hasPrefix("at://") else {
            throw SwanError.unauthorized("PLC terminal identity is incomplete")
        }
        let handle = String(alias.dropFirst("at://".count))
        guard try AccountIdentifiers.canonicalHandle(handle) == handle,
              let service = terminal.services["atproto_pds"],
              service.type == "AtprotoPersonalDataServer",
              let originURL = URL(string: service.endpoint) else {
            throw SwanError.unauthorized("PLC terminal identity is malformed")
        }
        let origin = try PLCATProfile.canonicalPDSOrigin(originURL)
        let generation = history.last?.signingKeyGeneration ?? 0
        guard generation > 0 else {
            throw SwanError.unauthorized("PLC terminal key generation is invalid")
        }
        return try PublicPLCIdentityState(
            genesisOperationCID: history[0].cid,
            terminalOperationCID: terminalCID,
            canonicalHandle: handle,
            pdsOrigin: origin,
            signingDIDKey: signingDIDKey,
            rotationDIDKey: rotationDIDKey,
            keyGeneration: generation
        )
    }
}
