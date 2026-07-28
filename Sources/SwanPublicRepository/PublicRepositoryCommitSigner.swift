import Crypto
import Foundation
import SwanCore

/// The repository commit codec is deliberately independent of account-key
/// lookup and of any particular signature implementation.
public enum PublicRepositorySigningAlgorithm: String, Sendable, Equatable {
    case p256
    case secp256k1
}

public protocol PublicRepositoryCommitSigner: Sendable {
    var signingAlgorithm: PublicRepositorySigningAlgorithm { get }

    /// Signs the exact canonical unsigned commit bytes. Implementations must
    /// not pre-hash these bytes before calling an ECDSA message-signing API.
    func sign(unsignedCommitBytes: Data) async throws -> Data
}

public protocol PublicRepositoryCommitVerifier: Sendable {
    var signingAlgorithm: PublicRepositorySigningAlgorithm { get }

    func verify(
        signature: Data,
        unsignedCommitBytes: Data,
        did: String
    ) async throws
}

/// Swan's current account repository-key adapter.
public struct P256PublicRepositoryCommitSigner: PublicRepositoryCommitSigner {
    public let signingAlgorithm: PublicRepositorySigningAlgorithm = .p256
    private let privateKey: P256.Signing.PrivateKey

    public init(privateKey: P256.Signing.PrivateKey) {
        self.privateKey = privateKey
    }

    public func sign(unsignedCommitBytes: Data) async throws -> Data {
        try P256WireSignature.sign(unsignedCommitBytes, using: privateKey)
    }
}

/// A verifier for an already-resolved P-256 repository signing key. DID
/// resolution and key rotation remain outside this pure repository target.
public struct P256PublicRepositoryCommitVerifier: PublicRepositoryCommitVerifier {
    public let signingAlgorithm: PublicRepositorySigningAlgorithm = .p256
    private let publicKey: P256.Signing.PublicKey

    public init(publicKey: P256.Signing.PublicKey) {
        self.publicKey = publicKey
    }

    public func verify(
        signature: Data,
        unsignedCommitBytes: Data,
        did _: String
    ) async throws {
        let decoded = try P256WireSignature.decodeCanonical(signature)
        guard publicKey.isValidSignature(decoded, for: unsignedCommitBytes) else {
            throw PublicRepositoryCommitError.invalidSignature
        }
    }
}
