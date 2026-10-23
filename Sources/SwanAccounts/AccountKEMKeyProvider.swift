import Crypto
import Foundation
import PetrelCrypto
import PetrelPLC
import SwanCore

/// Purpose-bound DHKEM custody. KEM keys are never used for repository or PLC signatures.
/// Generation one remains stable across signing/rotation-key changes.
public struct AccountKEMKeyProvider: Sendable {
    private let keyStore: any AccountKeyMaterialReader

    public init(keyStore: any AccountKeyMaterialReader) { self.keyStore = keyStore }

    public static func reference(accountDID: String) throws -> AccountKeyReference {
        try AccountKeyReference(accountDID: accountDID, purpose: .kem, generation: 1)
    }

    public func privateKey(accountDID: String) async throws -> P256.KeyAgreement.PrivateKey {
        try P256.KeyAgreement.PrivateKey(rawRepresentation: await keyStore.key(for: Self.reference(accountDID: accountDID)))
    }

    public static func didKey(_ publicKey: P256.KeyAgreement.PublicKey) throws -> String {
        // P-256 multicodec encodes the same curve point for both purposes. Only
        // public material crosses this conversion; private keys stay purpose-bound.
        P256DIDKey(publicKey: try P256.Signing.PublicKey(x963Representation: publicKey.x963Representation)).value
    }

    /// Public method for an externally managed did:web document. Publishing
    /// this projection requires the existing authenticated identity workflow.
    public func verificationMethod(accountDID: String, identityDID: String? = nil) async throws -> AccountKEMVerificationMethod {
        let did = try AccountIdentifiers.validateDID(identityDID ?? accountDID)
        let key = try await privateKey(accountDID: accountDID)
        return AccountKEMVerificationMethod(id: did + "#atproto_kem", controller: did,
            publicKeyMultibase: String(try Self.didKey(key.publicKey).dropFirst("did:key:".count)))
    }
}

public struct AccountKEMVerificationMethod: Codable, Sendable, Equatable {
    public let id: String
    public let type: String = "Multikey"
    public let controller: String
    public let publicKeyMultibase: String
}

/// Reconstructs the exact locally persisted genesis, including the optional
/// KEM method. Legacy journals retain their original DID and signature.
public enum SwanPLCGenesisCodec {
    public static func reconstructGenesis(signingDIDKey: String, rotationDIDKey: String,
        canonicalHandle: String, pdsOrigin: String, signature: String, kemDIDKey: String? = nil) throws -> PLCSignedOperation {
        var methods = ["atproto": signingDIDKey]
        if let kemDIDKey { methods["atproto_kem"] = kemDIDKey }
        let object: [String: Any] = [
            "type": "plc_operation", "rotationKeys": [rotationDIDKey], "verificationMethods": methods,
            "alsoKnownAs": ["at://" + canonicalHandle],
            "services": ["atproto_pds": ["type": "AtprotoPersonalDataServer", "endpoint": pdsOrigin]],
            "prev": NSNull(), "sig": signature,
        ]
        return try PLCOperationCodec.decodeSignedJSON(JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
    }
}
