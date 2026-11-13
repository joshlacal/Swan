import Crypto
import Foundation
import PetrelCrypto
import PetrelPLC
import SwanAccounts
import SwanCore

/// HPKE base-mode secret export for the Spaces response-MAC profile.
///
/// Swift Crypto exposes the required P-256 ECDH and HMAC primitives on both
/// macOS and Linux. This is the RFC 9180 export-only key schedule expanded into
/// those primitives, as specified by proposal 0016's appendix.
public enum SpaceMACKeyAgreement {
    public struct Encapsulation: Sendable, Equatable {
        public let keyID: String
        public let sharedSecret: Data
    }

    public enum Failure: Error, Sendable, Equatable {
        case invalidKey
    }

    private static let hpkeVersion = Data("HPKE-v1".utf8)
    private static let kemID = Data("KEM".utf8) + uint16(0x0010)
    private static let suiteID =
        Data("HPKE".utf8) + uint16(0x0010) + uint16(0x0001) + uint16(0xffff)
    private static let info = Data("atproto-mac".utf8)
    private static let empty = Data()
    private static let emptyExtractSalt = Data(repeating: 0, count: SHA256.byteCount)

    /// `SendExportBase`: creates a fresh `enc` and exports 32 bytes.
    public static func send(authorKeyID: String) throws -> Encapsulation {
        let author = try agreementPublicKey(authorKeyID)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let dh = try ephemeral.sharedSecretFromKeyAgreement(with: author)
        let keyID = try didKey(ephemeral.publicKey)
        return Encapsulation(
            keyID: keyID,
            sharedSecret: derive(
                dh: dh.withUnsafeBytes { Data($0) },
                enc: ephemeral.publicKey.x963Representation,
                authorPublicKey: author.x963Representation
            )
        )
    }

    /// `ReceiveExportBase`: decapsulates the compressed P-256 `did:key` from
    /// `keyid`, while the HPKE context uses both public keys uncompressed.
    public static func receive(
        authorPrivateKey: P256.KeyAgreement.PrivateKey,
        keyID: String
    ) throws -> Data {
        let enc = try agreementPublicKey(keyID)
        let dh = try authorPrivateKey.sharedSecretFromKeyAgreement(with: enc)
        return derive(
            dh: dh.withUnsafeBytes { Data($0) },
            enc: enc.x963Representation,
            authorPublicKey: authorPrivateKey.publicKey.x963Representation
        )
    }

    private static func derive(
        dh: Data,
        enc: Data,
        authorPublicKey: Data
    ) -> Data {
        let eaePRK = labeledExtract(id: kemID, salt: empty, label: "eae_prk", input: dh)
        let kemSecret = labeledExpand(
            id: kemID,
            pseudoRandomKey: eaePRK,
            label: "shared_secret",
            info: enc + authorPublicKey
        )
        let pskIDHash = labeledExtract(
            id: suiteID,
            salt: empty,
            label: "psk_id_hash",
            input: empty
        )
        let infoHash = labeledExtract(
            id: suiteID,
            salt: empty,
            label: "info_hash",
            input: info
        )
        let context = Data([0x00]) + pskIDHash + infoHash
        let secret = labeledExtract(
            id: suiteID,
            salt: kemSecret,
            label: "secret",
            input: empty
        )
        let exporterSecret = labeledExpand(
            id: suiteID,
            pseudoRandomKey: secret,
            label: "exp",
            info: context
        )
        return labeledExpand(
            id: suiteID,
            pseudoRandomKey: exporterSecret,
            label: "sec",
            info: empty
        )
    }

    private static func labeledExtract(
        id: Data,
        salt: Data,
        label: String,
        input: Data
    ) -> Data {
        var labeled = Data()
        labeled.reserveCapacity(hpkeVersion.count + id.count + label.utf8.count + input.count)
        labeled.append(hpkeVersion)
        labeled.append(id)
        labeled.append(contentsOf: label.utf8)
        labeled.append(input)
        return Data(HMAC<SHA256>.authenticationCode(
            for: labeled,
            using: SymmetricKey(data: salt.isEmpty ? emptyExtractSalt : salt)
        ))
    }

    /// Every expansion in this ciphersuite requests one SHA-256 block (32
    /// bytes), so RFC 5869 expansion is exactly one HMAC with counter `0x01`.
    private static func labeledExpand(
        id: Data,
        pseudoRandomKey: Data,
        label: String,
        info: Data
    ) -> Data {
        var labeled = Data()
        labeled.reserveCapacity(
            2 + hpkeVersion.count + id.count + label.utf8.count + info.count + 1
        )
        labeled.append(uint16(UInt16(SHA256.byteCount)))
        labeled.append(hpkeVersion)
        labeled.append(id)
        labeled.append(contentsOf: label.utf8)
        labeled.append(info)
        labeled.append(0x01)
        return Data(HMAC<SHA256>.authenticationCode(
            for: labeled,
            using: SymmetricKey(data: pseudoRandomKey)
        ))
    }

    private static func agreementPublicKey(
        _ keyID: String
    ) throws -> P256.KeyAgreement.PublicKey {
        do {
            return try P256.KeyAgreement.PublicKey(
                x963Representation: P256DIDKey(keyID).publicKey.x963Representation
            )
        } catch {
            throw Failure.invalidKey
        }
    }

    private static func didKey(_ key: P256.KeyAgreement.PublicKey) throws -> String {
        do {
            return P256DIDKey(
                publicKey: try P256.Signing.PublicKey(
                    x963Representation: key.x963Representation
                )
            ).value
        } catch {
            throw Failure.invalidKey
        }
    }

    private static func uint16(_ value: UInt16) -> Data {
        Data([UInt8(value >> 8), UInt8(value & 0xff)])
    }
}

/// Provides one operation: decapsulate a per-request HPKE export with an
/// account's dedicated KEM key after checking its lifecycle state.
public protocol SpaceRepositoryCommitSigner: Sendable {
    func sharedSecret(author: String, keyID: String) async throws -> Data
}

/// Local KEM secret provider backed by the encrypted account key store. The
/// account check is repeated after the suspending key read so deactivation
/// cannot race a response MAC.
public struct LocalAccountSpaceRepositoryCommitSigner:
    SpaceRepositoryCommitSigner
{
    private let accounts: DurableAccountDirectory
    private let keyStore: any AccountKeyStore

    public init(
        accounts: DurableAccountDirectory,
        keyStore: any AccountKeyStore
    ) {
        self.accounts = accounts
        self.keyStore = keyStore
    }

    public func sharedSecret(author: String, keyID: String) async throws -> Data {
        let author = try AccountIdentifiers.validateDID(author)
        guard let authorizing = try await accounts.authorizingAccount(did: author) else {
            throw SwanError.unauthorized("account KEM key is unavailable")
        }
        let key = try await AccountKEMKeyProvider(keyStore: keyStore).privateKey(accountDID: author)
        try await accounts.requireUnchangedAuthorizingAccount(did: author, expected: authorizing)
        return try SpaceMACKeyAgreement.receive(authorPrivateKey: key, keyID: keyID)
    }

}

