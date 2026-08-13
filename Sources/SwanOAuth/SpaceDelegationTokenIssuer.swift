import Crypto
import Foundation
import SwanAccounts
import SwanCore
import SwanSpaces

/// Mints a user-PDS delegation without exposing account private-key material
/// to HTTP, storage, or a general-purpose signing API.  Implementations
/// receive the already-authorized OAuth subject and exact space, then return
/// only the bounded compact JWT needed by `getSpaceCredential`.
public protocol SpaceDelegationTokenIssuer: Sendable {
    func issueDelegation(
        space: SpaceURI,
        issuer: String,
        now: Date
    ) async throws -> String
}

/// Local user-PDS issuer backed by the encrypted account key store.  The
/// control database contributes only lifecycle state and a generation
/// reference; the signing scalar is decrypted immediately before the compact
/// ES256 JWT is constructed and never crosses this narrow capability as
/// `Data` or becomes representable in configuration/SQLite/HTTP state.
public struct LocalAccountSpaceDelegationTokenIssuer: SpaceDelegationTokenIssuer {
    private let accounts: DurableAccountDirectory
    private let keyStore: any AccountKeyStore

    public init(
        accounts: DurableAccountDirectory,
        keyStore: any AccountKeyStore
    ) {
        self.accounts = accounts
        self.keyStore = keyStore
    }

    public func issueDelegation(
        space: SpaceURI,
        issuer: String,
        now: Date = Date()
    ) async throws -> String {
        let issuer = try AccountIdentifiers.validateDID(issuer)
        guard let authorizing = try await accounts.authorizingAccount(did: issuer) else {
            throw SwanError.unauthorized("delegation issuer is unavailable")
        }

        // The key-store read is a suspension: the account can be deactivated
        // or rekeyed while it runs.  The scalar is used immediately below, so
        // the account decision above is re-asserted the moment the read
        // returns and before anything is signed.
        let material = try await keyStore.key(for: authorizing.signing)
        try await accounts.requireUnchangedAuthorizingAccount(
            did: issuer,
            expected: authorizing
        )
        let privateKey: P256.Signing.PrivateKey
        do {
            privateKey = try P256.Signing.PrivateKey(rawRepresentation: material)
        } catch {
            throw SwanError.unavailable("delegation signing key is unavailable")
        }
        return try PermissionedDataJWT.createDelegationToken(
            issuer: issuer,
            audience: "\(space.authority)#atproto_space_host",
            space: space,
            key: privateKey,
            now: now,
            lifetime: PermissionedDataJWT.delegationLifetime
        )
    }
}
