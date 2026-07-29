import Crypto
import Foundation
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
        guard let did = serviceIssuerDID(issuer),
              let account = try await accounts.account(did: did),
              account.status.authorizesAccount,
              let references = try await accounts.keyReferences(did: did),
              let encoded = try await publicKeyStore.publicKey(for: references.signing) else {
            return nil
        }
        do {
            return .p256(try P256.Signing.PublicKey(x963Representation: encoded))
        } catch {
            throw SwanError.unavailable("service authentication key is unavailable")
        }
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
              let account = try await accounts.account(did: issuer),
              account.status.authorizesAccount,
              let references = try await accounts.keyReferences(did: issuer) else {
            throw SwanError.unauthorized("service authentication issuer is unavailable")
        }
        let material = try await keyStore.key(for: references.signing)
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

/// Strict compact service JWT parser/encoder. The pinned TypeScript verifier
/// permits ordinary `JWT` (and absent `typ`) while rejecting OAuth/DPoP token
/// types, accepts ES256K from the reference PDS, and requires `lxm` only at
/// the route verifier. Swan additionally requires a bounded JTI because it
/// is the durable notification idempotency key.
public enum SpaceServiceJWT {
    public static let maximumCompactBytes = 32 * 1024
    public static let lifetime: TimeInterval = 60

    public struct Inspection: Sendable, Equatable {
        public let issuer: String
        public let algorithm: String
        public let claims: Claims
    }

    public struct Claims: Codable, Sendable, Equatable {
        public let iss: String
        public let aud: String
        public let iat: Int64?
        public let exp: Int64
        public let lxm: String?
        public let jti: String?

        enum CodingKeys: String, CodingKey {
            case iss, aud, iat, exp, lxm, jti
        }
    }

    private struct Header: Codable, Sendable {
        let alg: String
        let typ: String?
        let kid: String?
        let crit: [String]?
        let b64: Bool?
    }

    private struct Parsed: Sendable {
        let header: Header
        let claims: Claims
        let signingInput: Data
        let signature: Data
    }

    public static func create(
        issuer: String,
        audience: String,
        method: String,
        eventID: String,
        key: P256.Signing.PrivateKey,
        now: Date = Date(),
        lifetime: TimeInterval = lifetime
    ) throws -> String {
        guard serviceIssuerDID(issuer) != nil,
              validServiceAudience(audience),
              validServiceMethod(method),
              validServiceEventID(eventID),
              lifetime > 0, lifetime <= Self.lifetime,
              lifetime.rounded(.towardZero) == lifetime else {
            throw SwanError.malformed("service authentication claims are invalid")
        }
        guard let iat = integerServiceTimestamp(now) else {
            throw SwanError.malformed(
                "service authentication current time is invalid"
            )
        }
        let expiration = iat.addingReportingOverflow(Int64(lifetime))
        guard !expiration.overflow else {
            throw SwanError.malformed(
                "service authentication claims are invalid"
            )
        }
        let claims = Claims(
            iss: issuer,
            aud: audience,
            iat: iat,
            exp: expiration.partialValue,
            lxm: method,
            jti: eventID
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let headerPart = try encoder.encode(Header(alg: "ES256", typ: "JWT", kid: nil, crit: nil, b64: nil)).base64URLEncodedString()
        let payloadPart = try encoder.encode(claims).base64URLEncodedString()
        let signingInput = Data("\(headerPart).\(payloadPart)".utf8)
        let signature = try P256WireSignature.sign(signingInput, using: key)
        return "\(headerPart).\(payloadPart).\(signature.base64URLEncodedString())"
    }

    public static func inspect(_ compact: String) throws -> Inspection {
        let parsed = try parse(compact)
        try validateShape(parsed.header, claims: parsed.claims)
        return Inspection(
            issuer: parsed.claims.iss,
            algorithm: parsed.header.alg,
            claims: parsed.claims
        )
    }

    public static func verify(
        _ compact: String,
        publicKey: PermissionedDataJWTVerificationKey,
        now: Date = Date(),
        clockSkew: TimeInterval = 60,
        maximumLifetime: TimeInterval = 5 * 60
    ) throws -> Claims {
        guard clockSkew >= 0, clockSkew <= 5 * 60,
              maximumLifetime > 0, maximumLifetime <= 10 * 60,
              clockSkew.isFinite, maximumLifetime.isFinite else {
            throw SwanError.malformed("service authentication time policy is invalid")
        }
        let parsed = try parse(compact)
        try validateShape(parsed.header, claims: parsed.claims)
        guard try publicKey.verifies(
            signature: parsed.signature,
            signingInput: parsed.signingInput,
            algorithm: parsed.header.alg
        ) else {
            throw SwanError.unauthorized("service authentication signature is invalid")
        }
        guard let nowSeconds = integerServiceTimestamp(now) else {
            throw SwanError.malformed(
                "service authentication current time is invalid"
            )
        }
        let skew = Int64(clockSkew)
        let expirationCutoff =
            nowSeconds.subtractingReportingOverflow(skew)
        guard !expirationCutoff.overflow else {
            throw SwanError.malformed(
                "service authentication time policy is invalid"
            )
        }
        guard parsed.claims.exp >= expirationCutoff.partialValue else {
            throw SwanError.expired
        }
        if let issuedAt = parsed.claims.iat {
            let latestIssuedAt = nowSeconds.addingReportingOverflow(skew)
            let lifetime =
                parsed.claims.exp.subtractingReportingOverflow(issuedAt)
            guard !latestIssuedAt.overflow,
                  issuedAt <= latestIssuedAt.partialValue,
                  parsed.claims.exp >= issuedAt,
                  !lifetime.overflow,
                  lifetime.partialValue <= Int64(maximumLifetime) else {
                throw SwanError.unauthorized("service authentication time claims are invalid")
            }
        }
        return parsed.claims
    }

    private static func integerServiceTimestamp(_ date: Date) -> Int64? {
        let timestamp = date.timeIntervalSince1970
        guard timestamp.isFinite,
              timestamp >= Double(Int64.min),
              timestamp < Double(Int64.max) else {
            return nil
        }
        return Int64(timestamp)
    }

    private static func parse(_ compact: String) throws -> Parsed {
        guard !compact.isEmpty, compact.utf8.count <= maximumCompactBytes else {
            throw SwanError.malformed("service authentication token is invalid")
        }
        let pieces = compact.split(separator: ".", omittingEmptySubsequences: false)
        guard pieces.count == 3,
              pieces.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 16 * 1024 }),
              let headerData = try? OAuthBase64URL.decode(String(pieces[0]), maxBytes: 4 * 1024),
              let payload = try? OAuthBase64URL.decode(String(pieces[1]), maxBytes: 16 * 1024),
              let signature = try? OAuthBase64URL.decode(String(pieces[2]), maxBytes: 64),
              signature.count == 64 else {
            throw SwanError.malformed("service authentication token is invalid")
        }
        let header = try StrictJSON.decode(Header.self, from: headerData)
        let claims = try StrictJSON.decode(Claims.self, from: payload)
        return Parsed(
            header: header,
            claims: claims,
            signingInput: Data("\(pieces[0]).\(pieces[1])".utf8),
            signature: signature
        )
    }

    private static func validateShape(_ header: Header, claims: Claims) throws {
        guard header.crit == nil, header.b64 == nil,
              header.alg == "ES256" || header.alg == "ES256K",
              !["at+jwt", "refresh+jwt", "dpop+jwt"].contains(header.typ?.lowercased() ?? ""),
              serviceIssuerDID(claims.iss) != nil,
              validServiceAudience(claims.aud),
              validServiceMethod(claims.lxm ?? ""),
              validServiceEventID(claims.jti ?? "") else {
            throw SwanError.unauthorized("service authentication token is invalid")
        }
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
