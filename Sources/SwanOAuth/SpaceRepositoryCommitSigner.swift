import Crypto
import Foundation
import SwanAccounts
import SwanCore
import SwanSpaces

/// Creates only the proposal-0016 reader-specific signed commit used by the
/// permissioned repository sync endpoints.  This intentionally is not a
/// general account signing interface: callers cannot select a payload, key
/// purpose, audience, or signature format.
public protocol SpaceRepositoryCommitSigner: Sendable {
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
/// intentionally repeated before the signing scalar is read so a stale
/// request cannot sign after deactivation or key-reference removal.
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
              let account = try await accounts.account(did: author),
              account.status.authorizesAccount,
              let references = try await accounts.keyReferences(did: author)
        else {
            throw SwanError.unauthorized("repository commit signer is unavailable")
        }

        // Do not retain or return the scalar.  It is decoded immediately into
        // Crypto's key value and used only for this fixed commit construction.
        let material = try await keyStore.key(for: references.signing)
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
