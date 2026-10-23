import Crypto
import Foundation
import PetrelCrypto
import PetrelPLC
import SwanAccounts
import SwanCore
import SwanSpaces

/// Creates only the proposal-0016 reader-specific signed commit used by the
/// permissioned repository sync endpoints.  This intentionally is not a
/// general account signing interface: callers cannot select a payload, key
/// purpose, audience, or signature format.
public protocol SpaceRepositoryCommitSigner: Sendable {
    /// Decapsulates only an account's dedicated KEM key after its lifecycle
    /// check. It never falls back to a signing key.
    func sharedSecret(author: String, keyShare: String) async throws -> Data

    func signRepositoryCommit(
        space: SpaceURI,
        author: String,
        wireRevision: String,
        commitment: Data
    ) async throws -> SpaceCommitEnvelope
}

/// Local commit signer backed by the encrypted account key store.  Lifecycle
/// and startup-preopen checks occur in the durable repository directory
/// before this capability is invoked.  This final account/reference check is
/// intentionally repeated around the signing scalar read — before it, so a
/// stale request never reaches the key store, and again after it, because the
/// read is a suspension during which a deactivation or key rotation can
/// commit.  The earlier check alone did not hold that invariant.
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

    public func sharedSecret(author: String, keyShare: String) async throws -> Data {
        let author = try AccountIdentifiers.validateDID(author)
        guard let authorizing = try await accounts.authorizingAccount(did: author) else {
            throw SwanError.unauthorized("account KEM key is unavailable")
        }
        let key = try await AccountKEMKeyProvider(keyStore: keyStore).privateKey(accountDID: author)
        try await accounts.requireUnchangedAuthorizingAccount(did: author, expected: authorizing)
        return try SpaceMAC.decapsulate(privateKey: key, keyShare: keyShare)
    }

    public func signRepositoryCommit(
        space: SpaceURI,
        author: String,
        wireRevision: String,
        commitment: Data
    ) async throws -> SpaceCommitEnvelope {
        let author = try AccountIdentifiers.validateDID(author)
        guard space.authority != "", commitment.count == 32,
              !wireRevision.isEmpty,
              wireRevision.utf8.count <= 128,
              let authorizing = try await accounts.authorizingAccount(did: author)
        else {
            throw SwanError.unauthorized("repository commit signer is unavailable")
        }

        // Do not retain or return the scalar.  It is decoded immediately into
        // Crypto's key value and used only for this fixed commit construction.
        // The read itself suspends, so the account decision above is
        // re-asserted before the commit is signed.
        let material = try await keyStore.key(for: authorizing.signing)
        try await accounts.requireUnchangedAuthorizingAccount(
            did: author,
            expected: authorizing
        )
        let privateKey: P256.Signing.PrivateKey
        do {
            privateKey = try P256.Signing.PrivateKey(rawRepresentation: material)
        } catch {
            throw SwanError.unavailable("repository commit signing key is unavailable")
        }
        return try SpaceCommitCodec.createReaderEnvelope(
            space: space,
            author: author,
            rev: wireRevision,
            commitment: commitment,
            key: privateKey
        )
    }
}

public extension SpaceRepositoryCommitSigner {
    func sharedSecret(author: String, keyShare: String) async throws -> Data {
        throw SwanError.unavailable("account KEM key is unavailable")
    }
}
