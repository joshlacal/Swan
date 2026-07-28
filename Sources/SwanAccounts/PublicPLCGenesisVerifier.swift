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
