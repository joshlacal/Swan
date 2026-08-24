import Crypto
import Foundation
import PetrelCrypto
import PetrelPLC
import SwanAccounts
import SwanCore
import SwanSpaces

/// The verified, route-bound subset of an AT Protocol service JWT. It is not
/// an OAuth authorization context: callers must still apply their endpoint's
/// `iss`, `aud`, and `lxm` requirements before invoking storage.
public struct VerifiedSpaceServiceAuthentication: Sendable, Equatable {
    public let issuer: String
    public let audience: String
    public let method: String
    public let eventID: String
    public let expiresAt: Date

    public init(
        issuer: String,
        audience: String,
        method: String,
        eventID: String,
        expiresAt: Date
    ) {
        self.issuer = issuer
        self.audience = audience
        self.method = method
        self.eventID = eventID
        self.expiresAt = expiresAt
    }
}

/// Resolves a service JWT verification key after bounded JWT inspection has
/// identified its issuer. Alpha resolvers are local-account or operator-pinned
/// only: an incoming notification never triggers DID/PLC/DNS/HTTP discovery.
public protocol SpaceServicePublicKeyResolver: Sendable {
    func publicKey(for issuer: String) async throws -> PermissionedDataJWTVerificationKey?
}

/// Verifies the exact service JWT shape accepted by the pinned PDS handlers.
/// It intentionally has no replay cache: notification idempotence is a
/// per-authority SQLite transaction so receiver restart and reordering retain
/// the same convergence behavior.
public protocol SpaceServiceAuthenticationVerifier: Sendable {
    func authenticate(
        _ compact: String,
        expectedAudience: String?,
        expectedMethod: String,
        now: Date
    ) async throws -> VerifiedSpaceServiceAuthentication
}

/// A small authority-scoped signer used only by durable notification
/// transports. It cannot sign arbitrary HTTP requests or arbitrary JWT
/// claims, and binds the outbox's stable event ID as the service JTI.
public protocol SpaceServiceAuthenticationIssuer: Sendable {
    func issue(
        issuer: String,
        audience: String,
        method: String,
        eventID: String,
        now: Date
    ) async throws -> String
}

/// Local verifier backed by authenticated public key metadata. Verification
/// never decrypts an account private key.
public struct LocalAccountSpaceServicePublicKeyResolver: SpaceServicePublicKeyResolver {
    private let accounts: DurableAccountDirectory
    private let publicKeyStore: any AccountKeyPublicKeyStore

    public init(accounts: DurableAccountDirectory, publicKeyStore: any AccountKeyPublicKeyStore) {
        self.accounts = accounts
        self.publicKeyStore = publicKeyStore
    }

    public func publicKey(for issuer: String) async throws -> PermissionedDataJWTVerificationKey? {
        // Only a *proven absence* from the local account directory may return
        // `nil`. `CompositeSpaceServicePublicKeyResolver` reads `nil` as
        // permission to use the operator pin, so reporting a deactivated,
        // deleted, unreadable, or key-less managed account as absence is what
        // lets a pin overlapping that DID keep verifying service JWTs after
        // the account it overlaps was revoked. Every other negative is
        // terminal. The credential and delegation resolvers in
        // `SpaceCredentialAuthority.swift` state and implement this contract;
        // this resolver was the odd one out.
        //
        // `SwanSpaceNotificationXRPC` maps `SwanError.unavailable` to 503 with
        // a fixed body, so this changes the status of an already-failing
        // request from 401 to 503 and widens nothing.
        guard let did = serviceIssuerDID(issuer) else {
            // Not a service-issuer DID at all, so not a managed identity —
            // and `PinnedSpaceServicePublicKey` rejects the same shape at
            // construction, so this cannot fall through onto a pin either.
            return nil
        }
        let authorizing: AuthorizingAccountSnapshot
        do {
            guard let managed = try await accounts.account(did: did) else {
                // The one proven absence, and so the one fall-through.
                return nil
            }
            guard managed.status.authorizesAccount,
                  let current = try await accounts.authorizingAccount(did: did),
                  current.account == managed else {
                throw SwanError.unavailable("service authentication key is unavailable")
            }
            authorizing = current
        } catch {
            throw SwanError.unavailable("service authentication key is unavailable")
        }

        let encoded: Data
        do {
            guard let current = try await publicKeyStore.publicKey(
                for: authorizing.signing
            ) else {
                throw SwanError.unavailable("service authentication key is unavailable")
            }
            encoded = current
        } catch {
            throw SwanError.unavailable("service authentication key is unavailable")
        }

        let verificationKey: PermissionedDataJWTVerificationKey
        do {
            verificationKey = .p256(
                try P256.Signing.PublicKey(x963Representation: encoded)
            )
        } catch {
            throw SwanError.unavailable("service authentication key is unavailable")
        }

        // The public-key read above is also a suspension. The two sibling
        // resolvers fence it; leaving this one unfenced would let a token
        // verify against a generation revoked while the metadata was in
        // flight.
        try await accounts.requireUnchangedAuthorizingAccount(
            did: did,
            expected: authorizing
        )
        return verificationKey
    }
}

/// An immutable offline key pin for the reference PDS or a configured lab
/// peer. Pinned values never enable request-time network resolution.
public struct PinnedSpaceServicePublicKey: Sendable {
    public let issuer: String
    public let generation: UInt64
    let key: PermissionedDataJWTVerificationKey

    public init(issuer: String, generation: UInt64, publicKey: P256.Signing.PublicKey) throws {
        guard serviceIssuerDID(issuer) != nil, generation > 0 else {
            throw SwanError.malformed("invalid pinned service authentication key")
        }
        self.issuer = issuer
        self.generation = generation
        key = .p256(publicKey)
    }

    public init(issuer: String, generation: UInt64, secp256k1PublicKey: Data) throws {
        guard serviceIssuerDID(issuer) != nil,
              generation > 0,
              PermissionedDataJWTVerificationKey.validatesSecp256k1PublicKey(secp256k1PublicKey) else {
            throw SwanError.malformed("invalid pinned service authentication key")
        }
        self.issuer = issuer
        self.generation = generation
        key = .secp256k1PublicKey(secp256k1PublicKey)
    }
}

public struct PinnedSpaceServicePublicKeyResolver: SpaceServicePublicKeyResolver {
    private let keys: [String: PermissionedDataJWTVerificationKey]

    public init(pins: [PinnedSpaceServicePublicKey]) throws {
        var selected: [String: (generation: UInt64, key: PermissionedDataJWTVerificationKey)] = [:]
        for pin in pins {
            if let current = selected[pin.issuer] {
                guard current.generation != pin.generation else {
                    throw SwanError.malformed("duplicate pinned service authentication key generation")
                }
                if pin.generation > current.generation {
                    selected[pin.issuer] = (pin.generation, pin.key)
                }
            } else {
                selected[pin.issuer] = (pin.generation, pin.key)
            }
        }
        keys = selected.mapValues(\.key)
    }

    public func publicKey(for issuer: String) async throws -> PermissionedDataJWTVerificationKey? {
        keys[issuer] ?? keys[serviceIssuerDID(issuer) ?? ""]
    }
}

public struct UnavailableSpaceServicePublicKeyResolver: SpaceServicePublicKeyResolver {
    public init() {}

    public func publicKey(for _: String) async throws -> PermissionedDataJWTVerificationKey? {
        nil
    }
}

public struct DurableSpaceServiceAuthenticationVerifier: SpaceServiceAuthenticationVerifier {
    public struct Configuration: Sendable, Equatable {
        public static let standard = Configuration(
            uncheckedClockSkew: 60,
            uncheckedMaximumLifetime: 5 * 60
        )

        public let clockSkew: TimeInterval
        public let maximumLifetime: TimeInterval

        public init(clockSkew: TimeInterval = 60, maximumLifetime: TimeInterval = 5 * 60) throws {
            guard clockSkew >= 0, clockSkew <= 5 * 60,
                  maximumLifetime > 0, maximumLifetime <= 10 * 60,
                  clockSkew.isFinite, maximumLifetime.isFinite else {
                throw SwanError.malformed("service authentication clock policy is invalid")
            }
            self.clockSkew = clockSkew
            self.maximumLifetime = maximumLifetime
        }

        private init(
            uncheckedClockSkew: TimeInterval,
            uncheckedMaximumLifetime: TimeInterval
        ) {
            clockSkew = uncheckedClockSkew
            maximumLifetime = uncheckedMaximumLifetime
        }
    }

    private let publicKeys: any SpaceServicePublicKeyResolver
    private let configuration: Configuration

    public init(
        publicKeys: any SpaceServicePublicKeyResolver,
        configuration: Configuration = .standard
    ) {
        self.publicKeys = publicKeys
        self.configuration = configuration
    }

    public func authenticate(
        _ compact: String,
        expectedAudience: String?,
        expectedMethod: String,
        now: Date = Date()
    ) async throws -> VerifiedSpaceServiceAuthentication {
        let inspected = try SpaceServiceJWT.inspect(compact)
        guard inspected.claims.lxm == expectedMethod,
              expectedAudience.map({ inspected.claims.aud == $0 }) ?? true,
              let key = try await publicKeys.publicKey(for: inspected.claims.iss) else {
            throw SwanError.unauthorized("service authentication is invalid")
        }
        let claims = try SpaceServiceJWT.verify(
            compact,
            publicKey: key,
            now: now,
            clockSkew: configuration.clockSkew,
            maximumLifetime: configuration.maximumLifetime
        )
        guard claims.lxm == expectedMethod,
              expectedAudience.map({ claims.aud == $0 }) ?? true,
              let eventID = claims.jti else {
            throw SwanError.unauthorized("service authentication is invalid")
        }
        return VerifiedSpaceServiceAuthentication(
            issuer: claims.iss,
            audience: claims.aud,
            method: expectedMethod,
            eventID: eventID,
            expiresAt: Date(timeIntervalSince1970: TimeInterval(claims.exp))
        )
    }
}

/// Local account-backed notification signer. The key is decrypted only after
/// the account/status/reference checks complete and is immediately consumed by
/// a fixed 60-second service JWT construction.
public struct LocalAccountSpaceServiceAuthenticationIssuer: SpaceServiceAuthenticationIssuer {
    private let accounts: DurableAccountDirectory
    private let keyStore: any AccountKeyStore

    public init(accounts: DurableAccountDirectory, keyStore: any AccountKeyStore) {
        self.accounts = accounts
        self.keyStore = keyStore
    }

    public func issue(
        issuer: String,
        audience: String,
        method: String,
        eventID: String,
        now: Date = Date()
    ) async throws -> String {
        let issuer = try AccountIdentifiers.validateDID(issuer)
        guard validServiceAudience(audience),
              validServiceMethod(method),
              validServiceEventID(eventID),
              let authorizing = try await accounts.authorizingAccount(did: issuer) else {
            throw SwanError.unauthorized("service authentication issuer is unavailable")
        }
        // The key-store read is a suspension during which a deactivation or a
        // key rotation can commit. Re-assert the account decision before the
        // token is signed, not only before the scalar is read.
        let material = try await keyStore.key(for: authorizing.signing)
        try await accounts.requireUnchangedAuthorizingAccount(
            did: issuer,
            expected: authorizing
        )
        let key: P256.Signing.PrivateKey
        do {
            key = try P256.Signing.PrivateKey(rawRepresentation: material)
        } catch {
            throw SwanError.unavailable("service authentication signing key is unavailable")
        }
        return try SpaceServiceJWT.create(
            issuer: issuer,
            audience: audience,
            method: method,
            eventID: eventID,
            key: key,
            now: now
        )
    }
}


private func serviceIssuerDID(_ value: String) -> String? {
    let parts = value.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)
    guard (1 ... 2).contains(parts.count),
          !parts[0].isEmpty,
          (parts.count == 1 || (!parts[1].isEmpty && parts[1].utf8.count <= 512)),
          let did = try? AccountIdentifiers.validateDID(String(parts[0])) else {
        return nil
    }
    return did
}

private func validServiceAudience(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 4_096 && value.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7e }
}

private func validServiceMethod(_ value: String) -> Bool {
    value.hasPrefix("com.atproto.") && value.utf8.count <= 317 && value.utf8.allSatisfy {
        ($0 >= UInt8(ascii: "a") && $0 <= UInt8(ascii: "z"))
            || ($0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z"))
            || ($0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9"))
            || $0 == UInt8(ascii: ".")
    }
}

private func validServiceEventID(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 256 && value.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7e }
}
