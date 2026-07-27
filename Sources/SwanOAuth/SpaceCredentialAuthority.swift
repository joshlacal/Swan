import Crypto
import Foundation
import SwanAccounts
import SwanCore
import SwanSpaces
import SwanStorage

/// The immutable authority-key facts required to sign one credential. The
/// P-256 private key is deliberately module-internal: callers can request a
/// credential but cannot serialize, log, or hand account key material to a
/// generic storage or HTTP API.
public struct SpaceCredentialAuthoritySigningKey: Sendable {
    public let authority: String
    public let keyID: String
    let privateKey: P256.Signing.PrivateKey

    init(
        authority: String,
        keyID: String = PermissionedDataJWT.spaceCredentialKeyID,
        privateKey: P256.Signing.PrivateKey
    ) {
        self.authority = authority
        self.keyID = keyID
        self.privateKey = privateKey
    }
}

/// Resolves an authority-owned signing key without making private key bytes
/// representable in a database model. Implementations may consult an
/// external key store, but they must never use a request as authority to
/// generate or persist a replacement key.
public protocol SpaceCredentialSigningKeyResolver: Sendable {
    func signingKey(
        for authority: String
    ) async throws -> SpaceCredentialAuthoritySigningKey?
}

/// Resolves the public material for a credential already inspected for its
/// exact type and fixed key ID. Remote implementations are intentionally
/// separate from SQLite policy evaluation: a future DID/PLC cache may fetch
/// outside this method's callers' transactions, but this alpha ships only
/// local and pinned resolvers.
public protocol SpaceCredentialPublicKeyResolver: Sendable {
    func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> P256.Signing.PublicKey?
}

/// The narrow signing boundary used by authority credential issuance. Its
/// output is a transient compact JWT, never a reader-specific envelope or a
/// durable database value.
public protocol SpaceCredentialAuthoritySigner: Sendable {
    func issueSpaceCredential(
        space: SpaceURI,
        user: String,
        authorization: AuthorizationContext,
        clientAttestation: String?,
        now: Date
    ) async throws -> String
}

/// The narrow bearer-token boundary used by future repository routes. It
/// returns a space credential context only after compact parsing, exact
/// issuer/space binding, public-key selection, signature verification, and
/// time validation have all succeeded.
public protocol SpaceCredentialAuthorizationVerifier: Sendable {
    func authorization(
        for token: String,
        expectedSpace: SpaceURI,
        now: Date
    ) async throws -> AuthorizationContext
}

/// A policy hook for resolving a client identity from a signed client
/// attestation. The implementation must return a client ID only after the
/// attestation's metadata/JWKS signature is verified. Swan deliberately
/// provides no optimistic parser-based implementation.
public protocol SpaceCredentialClientAttestationPolicy: Sendable {
    func verifiedClientID(
        for clientAttestation: String?,
        authority: String,
        now: Date
    ) async throws -> String?
}

/// Default alpha policy: no signed client JWKS resolver exists yet, so an
/// attestation cannot establish an application identity. `nil` remains valid
/// for spaces with open app access; allow-listed spaces then fail through the
/// durable authority policy rather than trusting an unverified client claim.
public struct UnavailableSpaceCredentialClientAttestationPolicy:
    SpaceCredentialClientAttestationPolicy
{
    public init() {}

    public func verifiedClientID(
        for clientAttestation: String?,
        authority _: String,
        now _: Date
    ) async throws -> String? {
        guard clientAttestation == nil else {
            throw SwanError.unavailable(
                "client attestation verification is unavailable"
            )
        }
        return nil
    }
}

/// A local resolver joins durable account generation references to encrypted
/// key-store material. `control.sqlite` contains only the reference; the
/// private scalar is read from ``AccountKeyStore`` immediately before signing
/// or deriving a local verification key and is never returned as `Data`.
public struct LocalAccountSpaceCredentialKeyResolver:
    SpaceCredentialSigningKeyResolver,
    SpaceCredentialPublicKeyResolver
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

    public func signingKey(
        for authority: String
    ) async throws -> SpaceCredentialAuthoritySigningKey? {
        guard let account = try await accounts.account(did: authority),
              account.status.authorizesAccount,
              let references = try await accounts.keyReferences(did: authority)
        else {
            return nil
        }
        let material = try await keyStore.key(for: references.signing)
        let privateKey: P256.Signing.PrivateKey
        do {
            privateKey = try P256.Signing.PrivateKey(rawRepresentation: material)
        } catch {
            throw SwanError.unavailable("space credential signing key is unavailable")
        }
        return SpaceCredentialAuthoritySigningKey(
            authority: authority,
            privateKey: privateKey
        )
    }

    public func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> P256.Signing.PublicKey? {
        guard keyID == PermissionedDataJWT.spaceCredentialKeyID,
              let signing = try await signingKey(for: issuer) else {
            return nil
        }
        return signing.privateKey.publicKey
    }
}

/// A static, offline public-key resolver for pinned interop fixtures and
/// explicitly configured local peers. It never attempts DID, PLC, DNS, or
/// HTTP resolution. When several generations for one `(authority, kid)` are
/// provided, the highest generation is selected so an operator can replace a
/// pinned key without an ambiguous cache entry.
public struct PinnedSpaceCredentialPublicKey: Sendable {
    public let authority: String
    public let keyID: String
    public let generation: UInt64
    let publicKey: P256.Signing.PublicKey

    public init(
        authority: String,
        keyID: String = PermissionedDataJWT.spaceCredentialKeyID,
        generation: UInt64,
        publicKey: P256.Signing.PublicKey
    ) throws {
        guard (try? AccountIdentifiers.validateDID(authority)) != nil,
              keyID == PermissionedDataJWT.spaceCredentialKeyID,
              generation > 0 else {
            throw SwanError.malformed("invalid pinned space credential key")
        }
        self.authority = authority
        self.keyID = keyID
        self.generation = generation
        self.publicKey = publicKey
    }
}

public struct PinnedSpaceCredentialPublicKeyResolver:
    SpaceCredentialPublicKeyResolver
{
    private let keys: [PinnedKey: P256.Signing.PublicKey]

    public init(pins: [PinnedSpaceCredentialPublicKey]) throws {
        var selected: [PinnedKey: (generation: UInt64, key: P256.Signing.PublicKey)] = [:]
        for pin in pins {
            let identity = PinnedKey(authority: pin.authority, keyID: pin.keyID)
            if let existing = selected[identity] {
                guard existing.generation != pin.generation else {
                    throw SwanError.malformed("duplicate pinned space credential key generation")
                }
                if pin.generation > existing.generation {
                    selected[identity] = (pin.generation, pin.publicKey)
                }
            } else {
                selected[identity] = (pin.generation, pin.publicKey)
            }
        }
        keys = selected.mapValues(\.key)
    }

    public func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> P256.Signing.PublicKey? {
        keys[PinnedKey(authority: issuer, keyID: keyID)]
    }

    private struct PinnedKey: Hashable, Sendable {
        let authority: String
        let keyID: String
    }
}

/// Explicitly refuses remote authority resolution. This is the only default
/// remote behavior until a future DID/PLC cache can satisfy the same limits
/// and SSRF controls as Swan's OAuth metadata loader.
public struct UnavailableSpaceCredentialPublicKeyResolver:
    SpaceCredentialPublicKeyResolver
{
    public init() {}

    public func publicKey(
        for _: String,
        keyID _: String
    ) async throws -> P256.Signing.PublicKey? {
        nil
    }
}

/// Issues proposal-shaped space credentials after the authority's durable
/// policy has permitted the exact reader/app tuple. There is intentionally no
/// arbitrary `clientID` parameter: client identity enters only through the
/// separately verifiable attestation policy.
public struct DurableSpaceCredentialAuthority: SpaceCredentialAuthoritySigner {
    public struct Configuration: Sendable, Equatable {
        public static let standard = Configuration(uncheckedLifetime: PermissionedDataJWT.spaceCredentialLifetime)

        public let lifetime: TimeInterval

        public init(lifetime: TimeInterval = PermissionedDataJWT.spaceCredentialLifetime) throws {
            guard lifetime > 0,
                  lifetime <= PermissionedDataJWT.spaceCredentialLifetime,
                  lifetime.rounded(.towardZero) == lifetime else {
                throw SwanError.malformed("invalid space credential lifetime")
            }
            self.lifetime = lifetime
        }

        private init(uncheckedLifetime: TimeInterval) {
            lifetime = uncheckedLifetime
        }
    }

    private let policyDirectory: any AuthorizedSimpleSpaceCredentialDirectory
    private let signingKeys: any SpaceCredentialSigningKeyResolver
    private let clientAttestationPolicy: any SpaceCredentialClientAttestationPolicy
    private let configuration: Configuration

    public init(
        policyDirectory: any AuthorizedSimpleSpaceCredentialDirectory,
        signingKeys: any SpaceCredentialSigningKeyResolver,
        clientAttestationPolicy: any SpaceCredentialClientAttestationPolicy = UnavailableSpaceCredentialClientAttestationPolicy(),
        configuration: Configuration = .standard
    ) {
        self.policyDirectory = policyDirectory
        self.signingKeys = signingKeys
        self.clientAttestationPolicy = clientAttestationPolicy
        self.configuration = configuration
    }

    public func issueSpaceCredential(
        space: SpaceURI,
        user: String,
        authorization: AuthorizationContext,
        clientAttestation: String? = nil,
        now: Date = Date()
    ) async throws -> String {
        // A JWT space credential has no reader subject claim. It therefore
        // must not be accepted as proof that some caller may mint another
        // credential. The future delegation-token boundary will construct a
        // distinct validated requester context; this foundation accepts only
        // the direct account principal and binds it to `user` here.
        guard case let .accountOAuth(subject, _) = authorization,
              subject == user,
              (try? AccountIdentifiers.validateDID(user)) != nil else {
            throw SwanError.unauthorized("credential requester does not match the requested user")
        }
        let clientID = try await clientAttestationPolicy.verifiedClientID(
            for: clientAttestation,
            authority: space.authority,
            now: now
        )
        try await policyDirectory.authorizeSimpleSpaceCredentialRead(
            space: space,
            user: user,
            clientID: clientID,
            authorization: authorization
        )
        guard let signingKey = try await signingKeys.signingKey(for: space.authority),
              signingKey.authority == space.authority,
              signingKey.keyID == PermissionedDataJWT.spaceCredentialKeyID else {
            throw SwanError.unavailable("space credential signing key is unavailable")
        }
        return try PermissionedDataJWT.createSpaceCredential(
            issuer: space.authority,
            space: space,
            key: signingKey.privateKey,
            now: now,
            lifetime: configuration.lifetime,
            kid: signingKey.keyID
        )
    }
}

/// Converts a verified compact space credential into the domain's explicit
/// read-only authorization context. The `SpaceGrant.subject` is the authority
/// issuer because proposal 0016 credentials intentionally contain no reader
/// identity; issuance is separately bound to a reader by
/// ``DurableSpaceCredentialAuthority`` and is never inferred during bearer
/// verification.
public struct DurableSpaceCredentialVerifier: SpaceCredentialAuthorizationVerifier {
    public struct Configuration: Sendable, Equatable {
        public static let standard = Configuration(uncheckedClockSkew: 60)

        public let clockSkew: TimeInterval

        public init(clockSkew: TimeInterval = 60) throws {
            guard (0 ... 5 * 60).contains(clockSkew) else {
                throw SwanError.malformed("invalid space credential clock skew")
            }
            self.clockSkew = clockSkew
        }

        private init(uncheckedClockSkew: TimeInterval) {
            clockSkew = uncheckedClockSkew
        }
    }

    private let publicKeys: any SpaceCredentialPublicKeyResolver
    private let configuration: Configuration

    public init(
        publicKeys: any SpaceCredentialPublicKeyResolver,
        configuration: Configuration = .standard
    ) {
        self.publicKeys = publicKeys
        self.configuration = configuration
    }

    public func authorization(
        for token: String,
        expectedSpace: SpaceURI,
        now: Date = Date()
    ) async throws -> AuthorizationContext {
        let inspection = try PermissionedDataJWT.inspectSpaceCredential(token)
        guard inspection.claims.iss == expectedSpace.authority,
              inspection.claims.sub == expectedSpace.rawValue else {
            throw SwanError.unauthorized("space credential does not match the requested space")
        }
        guard let publicKey = try await publicKeys.publicKey(
            for: inspection.claims.iss,
            keyID: inspection.header.kid ?? ""
        ) else {
            // Do not attempt remote resolution from an auth path. The caller
            // cannot distinguish an absent remote key from a disabled cache.
            throw SwanError.unavailable("space credential verification key is unavailable")
        }
        let claims = try PermissionedDataJWT.verifySpaceCredential(
            token,
            publicKey: publicKey,
            expectedSpace: expectedSpace,
            now: now,
            clockSkew: configuration.clockSkew
        )
        return .spaceCredential(
            SpaceGrant(
                subject: claims.iss,
                space: expectedSpace,
                permissions: [.read],
                expiresAt: Date(timeIntervalSince1970: TimeInterval(claims.exp))
            )
        )
    }
}
