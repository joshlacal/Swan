import Crypto
import Foundation
import PetrelPLC
import SwanAccounts
import SwanCore

/// Inter-service auth for proxied XRPC, mirroring
/// `com.atproto.server.getServiceAuth`.
///
/// Deliberately separate from `SpaceServiceJWT`, whose method validator is
/// restricted to `com.atproto.*` to guard Swan's own space-service path.
/// Widening that validator would loosen a control on traffic Swan *verifies*;
/// this type only *mints* tokens that a remote service verifies, so a general
/// NSID space here weakens nothing on this host.
public enum ProxyServiceJWT {
    public static let maximumLifetime: TimeInterval = 60

    private struct Header: Encodable {
        let alg = "ES256"
        let typ = "JWT"
    }

    private struct Claims: Encodable {
        let iss: String
        let aud: String
        let lxm: String
        let jti: String
        let iat: Int64
        let exp: Int64
    }

    public static func create(
        issuer: String,
        audience: String,
        method: String,
        eventID: String,
        key: P256.Signing.PrivateKey,
        now: Date = Date(),
        lifetime: TimeInterval = maximumLifetime
    ) throws -> String {
        guard isValidDID(issuer),
              isPrintable(audience, maximumBytes: 4096),
              isValidNSID(method),
              isPrintable(eventID, maximumBytes: 256),
              lifetime > 0, lifetime <= maximumLifetime,
              lifetime.rounded(.towardZero) == lifetime,
              now.timeIntervalSince1970.isFinite
        else {
            throw SwanError.malformed("proxy service authentication claims are invalid")
        }
        let iat = Int64(now.timeIntervalSince1970.rounded(.towardZero))
        let (exp, overflow) = iat.addingReportingOverflow(Int64(lifetime))
        guard !overflow else {
            throw SwanError.malformed("proxy service authentication expiry is invalid")
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let header = try encoder.encode(Header())
        let claims = try encoder.encode(
            Claims(iss: issuer, aud: audience, lxm: method, jti: eventID, iat: iat, exp: exp)
        )
        let signingInput = "\(base64URL(header)).\(base64URL(claims))"
        let signature = try key.signature(for: Data(signingInput.utf8))
        return "\(signingInput).\(base64URL(signature.rawRepresentation))"
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func isPrintable(_ value: String, maximumBytes: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maximumBytes
            && value.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7E }
    }

    private static func isValidDID(_ value: String) -> Bool {
        value.hasPrefix("did:") && isPrintable(value, maximumBytes: 2048)
            && !value.contains("#")
    }

    /// The same NSID grammar this type binds into `lxm`, exposed so a caller
    /// can reject a non-NSID request target *before* it reaches routing. A
    /// second, subtly different validator in the HTTP layer would let a shape
    /// through here that `create` then refuses at signing time.
    public static func isNSID(_ value: String) -> Bool { isValidNSID(value) }

    /// Dotted segments of alphanumerics/hyphen, at least three segments.
    private static func isValidNSID(_ value: String) -> Bool {
        guard value.utf8.count <= 317 else { return false }
        let segments = value.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count >= 3 else { return false }
        return segments.allSatisfy { segment in
            !segment.isEmpty
                && segment.utf8.allSatisfy {
                    ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z"))
                        || ($0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z"))
                        || ($0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9"))
                        || $0 == UInt8(ascii: "-")
                }
        }
    }
}

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
