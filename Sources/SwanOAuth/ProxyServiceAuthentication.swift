import Crypto
import Foundation
import PetrelCrypto
import PetrelPLC
import SwanAccounts
import SwanCore


/// Mints the one short-lived service token a proxied XRPC request carries.
///
/// This is the same shape as ``SpaceDelegationTokenIssuer``: the HTTP layer
/// receives only "give me a token for this already-authorized subject and this
/// exact audience/method", never an account signing key or a database handle.
public protocol SwanProxyServiceTokenIssuing: Sendable {
    func issueProxyServiceToken(
        issuer: String,
        audience: String,
        method: String,
        now: Date
    ) async throws -> String

    /// Optional bounded expiry requested by `getServiceAuth`. Existing
    /// issuers keep the original default implementation; the account-key
    /// issuer overrides it so a valid `exp` is reflected in the signed
    /// claims instead of being silently widened to the 60-second default.
    func issueProxyServiceToken(
        issuer: String,
        audience: String,
        method: String,
        now: Date,
        requestedExpiry: Date?
    ) async throws -> String
}

public extension SwanProxyServiceTokenIssuing {
    func issueProxyServiceToken(
        issuer: String,
        audience: String,
        method: String,
        now: Date,
        requestedExpiry: Date?
    ) async throws -> String {
        guard requestedExpiry == nil else {
            throw SwanError.unavailable(
                "service-auth requested expiry is unsupported by this issuer"
            )
        }
        return try await issueProxyServiceToken(
            issuer: issuer,
            audience: audience,
            method: method,
            now: now
        )
    }
}

/// Local issuer backed by the encrypted account key store. The control
/// database contributes only lifecycle state and a key reference; the signing
/// scalar is decrypted immediately before the compact ES256 JWT is built and
/// never becomes representable in configuration, SQLite, or HTTP state.
public struct LocalAccountProxyServiceTokenIssuer: SwanProxyServiceTokenIssuing {
    private let accounts: DurableAccountDirectory
    private let keyStore: any AccountKeyStore

    public init(
        accounts: DurableAccountDirectory,
        keyStore: any AccountKeyStore
    ) {
        self.accounts = accounts
        self.keyStore = keyStore
    }

    public func issueProxyServiceToken(
        issuer: String,
        audience: String,
        method: String,
        now: Date = Date()
    ) async throws -> String {
        try await issueProxyServiceToken(
            issuer: issuer,
            audience: audience,
            method: method,
            now: now,
            requestedExpiry: nil
        )
    }

    public func issueProxyServiceToken(
        issuer: String,
        audience: String,
        method: String,
        now: Date,
        requestedExpiry: Date?
    ) async throws -> String {
        let issuer = try AccountIdentifiers.validateDID(issuer)
        guard let authorizing = try await accounts.authorizingAccount(did: issuer) else {
            throw SwanError.unauthorized("proxy service token issuer is unavailable")
        }

        // The key-store read is a suspension: the account can be deactivated
        // or rekeyed while it runs. The scalar is used immediately below, so
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
            throw SwanError.unavailable("proxy service signing key is unavailable")
        }
        let issuedSeconds = now.timeIntervalSince1970
        guard issuedSeconds.isFinite,
              issuedSeconds >= Double(Int64.min),
              issuedSeconds <= Double(Int64.max) else {
            throw SwanError.malformed("proxy service authentication time is invalid")
        }
        guard let issuedEpoch = Int64(exactly: issuedSeconds.rounded(.towardZero)) else {
            throw SwanError.malformed("proxy service authentication time is invalid")
        }
        let lifetime: TimeInterval
        if let requestedExpiry {
            let expirySeconds = requestedExpiry.timeIntervalSince1970
            guard expirySeconds.isFinite,
                  expirySeconds >= Double(Int64.min),
                  expirySeconds <= Double(Int64.max) else {
                throw SwanError.malformed("proxy service authentication expiry is invalid")
            }
            guard let expiryEpoch = Int64(exactly: expirySeconds.rounded(.towardZero)) else {
                throw SwanError.malformed("proxy service authentication expiry is invalid")
            }
            guard expiryEpoch > issuedEpoch,
                  expiryEpoch <= issuedEpoch + Int64(ProxyServiceJWT.maximumLifetime) else {
                throw SwanError.malformed("proxy service authentication expiry is invalid")
            }
            lifetime = TimeInterval(expiryEpoch - issuedEpoch)
        } else {
            lifetime = ProxyServiceJWT.maximumLifetime
        }
        return try ProxyServiceJWT.create(
            issuer: issuer,
            audience: audience,
            method: method,
            // A fresh jti per request. The remote service uses it for replay
            // rejection, so it must never be derived from the request.
            eventID: UUID().uuidString,
            key: privateKey,
            now: now,
            lifetime: lifetime
        )
    }
}
