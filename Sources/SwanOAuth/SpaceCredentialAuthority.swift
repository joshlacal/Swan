import Crypto
import Foundation
import PetrelCrypto
import PetrelPLC
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

/// Opaque terminal failure for a credential-key authority which was found but
/// cannot currently authorize verification. The single case deliberately does
/// not reveal lifecycle, key-generation, or key-store details to callers.
public enum SpaceCredentialPublicKeyResolutionError:
    Error, Sendable, Equatable
{
    case unavailable
}

/// Opaque terminal failure for a locally managed delegation issuer which was
/// found but cannot currently authorize verification. A managed account must
/// never fall through to an operator pin or remote PLC key when its lifecycle,
/// generation metadata, or public key projection is unavailable.
public enum SpaceDelegationPublicKeyResolutionError:
    Error, Sendable, Equatable
{
    case unavailable
}

/// Resolves the public material for a credential already inspected for its
/// exact type and accepted dedicated-or-fallback key ID. When used as the
/// authoritative local source in a composite, `nil` has the narrow meaning
/// "this resolver does not manage the issuer"; a local resolver which does
/// manage the issuer must throw on every unsupported, inactive, missing, or
/// corrupt state so composition cannot fall through to another authority.
/// Remote implementations are intentionally separate from SQLite policy
/// evaluation.
public protocol SpaceCredentialPublicKeyResolver: Sendable {
    func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> PermissionedDataJWTVerificationKey?
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

/// Resolves the public material for an inspected user-to-space-host
/// delegation. This is a separate protocol from
/// ``SpaceCredentialPublicKeyResolver`` because delegations are signed by the
/// user's `#atproto` key while space credentials are signed by an authority's
/// dedicated `#atproto_space` key. Implementations may be local,
/// operator-pinned, or explicitly startup-bound to a PLC. Any remote
/// implementation must keep its issuer allowlist, transport policy,
/// continuity checks, and cache bounds outside request input; the protocol
/// itself never authorizes a request to choose a DID, PLC, DNS, or HTTP source.
public protocol SpaceDelegationPublicKeyResolver: Sendable {
    func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> PermissionedDataJWTVerificationKey?
}

/// A delegation whose compact JWT signature, issuer, audience, space,
/// lifetime, and opaque nonce have all been verified. It still is not a
/// repository grant: only the authority exchange can consume its JTI and pass
/// the deliberately narrow authorization to credential policy.
public struct VerifiedSpaceDelegation: Sendable {
    public let authorization: AuthorizationContext
    public let issuer: String
    public let audience: String
    public let space: SpaceURI
    public let jti: String
    public let expiresAt: Date

    init(
        authorization: AuthorizationContext,
        issuer: String,
        audience: String,
        space: SpaceURI,
        jti: String,
        expiresAt: Date
    ) {
        self.authorization = authorization
        self.issuer = issuer
        self.audience = audience
        self.space = space
        self.jti = jti
        self.expiresAt = expiresAt
    }
}

/// Verifies one compact delegation and returns the deliberately narrow
/// requester context that can be exchanged at a space authority. The context
/// is never a repository grant and cannot be used for record I/O directly.
public protocol SpaceDelegationAuthorizationVerifier: Sendable {
    func verifiedDelegation(
        for token: String,
        expectedSpace: SpaceURI,
        now: Date
    ) async throws -> VerifiedSpaceDelegation
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
            throw SpaceCredentialClientAttestationFailure.invalid
        }
        return nil
    }
}

/// A local signing resolver joins durable account generation references to
/// encrypted key-store material. `control.sqlite` contains only the reference;
/// the private scalar is read from ``AccountKeyStore`` immediately before
/// signing and is never returned as `Data`.
public struct LocalAccountSpaceCredentialSigningKeyResolver:
    SpaceCredentialSigningKeyResolver
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
        // The key-store read above is a suspension, and the directory exposes
        // no atomic account/key projection, so deactivation, permanent-deletion
        // revocation, or a key rotation can commit while it runs. Re-read the
        // account and its key references and treat any intervening change as
        // terminal: the caller signs a two-hour credential immediately on
        // return, and a credential signed under a revoked authority outlives
        // the revocation that should have prevented it. The verification
        // resolvers below apply exactly this fence twice (`:304-317`,
        // `:397-410`); the signing path was the odd one out.
        //
        // This throws rather than returning `nil`. A `nil` from this resolver
        // means "no such managed authority" and is a fall-through; a state that
        // changed underneath us is a hard negative that must not be confused
        // with absence. `SwanSpaceCredentialXRPC` already maps
        // `SwanError.unavailable` without widening the client-visible body.
        guard let currentAccount = try await accounts.account(did: authority),
              currentAccount == account,
              currentAccount.status.authorizesAccount,
              let currentReferences = try await accounts.keyReferences(did: authority),
              currentReferences.signing == references.signing,
              currentReferences.rotation == references.rotation
        else {
            throw SwanError.unavailable("space credential signing key is unavailable")
        }
        return SpaceCredentialAuthoritySigningKey(
            authority: authority,
            privateKey: privateKey
        )
    }

}

/// A local verification resolver joins the same durable account generation
/// references to authenticated public-key metadata. Its static dependency is
/// deliberately ``AccountKeyPublicKeyStore`` rather than ``AccountKeyStore``:
/// verification cannot cause a private signing scalar to be decrypted.
public struct LocalAccountSpaceCredentialPublicKeyResolver:
    SpaceCredentialPublicKeyResolver
{
    private let accounts: DurableAccountDirectory
    private let publicKeyStore: any AccountKeyPublicKeyStore

    public init(
        accounts: DurableAccountDirectory,
        publicKeyStore: any AccountKeyPublicKeyStore
    ) {
        self.accounts = accounts
        self.publicKeyStore = publicKeyStore
    }

    public func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> PermissionedDataJWTVerificationKey? {
        let account: AccountControlAccount
        do {
            guard let managed = try await accounts.account(did: issuer) else {
                // Only a proven absence from the local account directory may
                // fall through to an operator pin or remote PLC resolver.
                return nil
            }
            account = managed
        } catch {
            throw SpaceCredentialPublicKeyResolutionError.unavailable
        }

        guard account.status.authorizesAccount,
              keyID == PermissionedDataJWT.spaceCredentialKeyID
                || keyID == PermissionedDataJWT.spaceCredentialFallbackKeyID,
              let expectedSigning = account.signingKey,
              let expectedRotation = account.rotationKey,
              expectedSigning.generation == expectedRotation.generation else {
            throw SpaceCredentialPublicKeyResolutionError.unavailable
        }

        let references: (signing: AccountKeyReference, rotation: AccountKeyReference)
        do {
            guard let current = try await accounts.keyReferences(did: issuer),
                  current.signing.generation == expectedSigning.generation,
                  current.rotation.generation == expectedRotation.generation else {
                throw SpaceCredentialPublicKeyResolutionError.unavailable
            }
            references = current
        } catch {
            throw SpaceCredentialPublicKeyResolutionError.unavailable
        }

        let encoded: Data
        do {
            guard let current = try await publicKeyStore.publicKey(
                for: references.signing
            ) else {
                throw SpaceCredentialPublicKeyResolutionError.unavailable
            }
            encoded = current
        } catch {
            throw SpaceCredentialPublicKeyResolutionError.unavailable
        }

        let verificationKey: PermissionedDataJWTVerificationKey
        do {
            verificationKey = .p256(
                try P256.Signing.PublicKey(x963Representation: encoded)
            )
        } catch {
            throw SpaceCredentialPublicKeyResolutionError.unavailable
        }

        // The directory does not currently expose one atomic account/key
        // projection. Re-read the complete account generation and lifecycle
        // after the external metadata read, and treat any intervening change
        // as a terminal local negative. A caller may retry against the new
        // generation; it must never verify through an old pin or remote key.
        do {
            guard let currentAccount = try await accounts.account(did: issuer),
                  currentAccount == account,
                  currentAccount.status.authorizesAccount else {
                throw SpaceCredentialPublicKeyResolutionError.unavailable
            }
        } catch {
            throw SpaceCredentialPublicKeyResolutionError.unavailable
        }
        return verificationKey
    }
}

/// Local public-key resolver for a user's `#atproto` delegation key. It uses
/// the same authenticated public metadata projection as credential
/// verification, so a delegation request cannot decrypt a private account
/// scalar merely to validate a signature.
public struct LocalAccountSpaceDelegationPublicKeyResolver:
    SpaceDelegationPublicKeyResolver
{
    private let accounts: DurableAccountDirectory
    private let publicKeyStore: any AccountKeyPublicKeyStore

    public init(
        accounts: DurableAccountDirectory,
        publicKeyStore: any AccountKeyPublicKeyStore
    ) {
        self.accounts = accounts
        self.publicKeyStore = publicKeyStore
    }

    public func publicKey(
        for issuer: String,
        keyID: String
    ) async throws -> PermissionedDataJWTVerificationKey? {
        let account: AccountControlAccount
        do {
            guard let managed = try await accounts.account(did: issuer) else {
                // Only a proven absence from the local account directory may
                // fall through to an operator pin or remote PLC resolver.
                return nil
            }
            account = managed
        } catch {
            throw SpaceDelegationPublicKeyResolutionError.unavailable
        }

        guard account.status.authorizesAccount,
              keyID == PermissionedDataJWT.delegationKeyID,
              let expectedSigning = account.signingKey,
              let expectedRotation = account.rotationKey,
              expectedSigning.generation == expectedRotation.generation else {
            throw SpaceDelegationPublicKeyResolutionError.unavailable
        }

        let references: (signing: AccountKeyReference, rotation: AccountKeyReference)
        do {
            guard let current = try await accounts.keyReferences(did: issuer),
                  current.signing.generation == expectedSigning.generation,
                  current.rotation.generation == expectedRotation.generation else {
                throw SpaceDelegationPublicKeyResolutionError.unavailable
            }
            references = current
        } catch {
            throw SpaceDelegationPublicKeyResolutionError.unavailable
        }

        let encoded: Data
        do {
            guard let current = try await publicKeyStore.publicKey(
                for: references.signing
            ) else {
                throw SpaceDelegationPublicKeyResolutionError.unavailable
            }
            encoded = current
        } catch {
            throw SpaceDelegationPublicKeyResolutionError.unavailable
        }

        let verificationKey: PermissionedDataJWTVerificationKey
        do {
            verificationKey = .p256(
                try P256.Signing.PublicKey(x963Representation: encoded)
            )
        } catch {
            throw SpaceDelegationPublicKeyResolutionError.unavailable
        }

        // The directory does not currently expose one atomic account/key
        // projection. Re-read the complete account generation and lifecycle
        // after the external metadata read, and treat any intervening change
        // as a terminal local negative. A caller may retry against the new
        // generation; it must never verify through an old pin or remote key.
        do {
            guard let currentAccount = try await accounts.account(did: issuer),
                  currentAccount == account,
                  currentAccount.status.authorizesAccount else {
                throw SpaceDelegationPublicKeyResolutionError.unavailable
            }
        } catch {
            throw SpaceDelegationPublicKeyResolutionError.unavailable
        }
        return verificationKey
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
    let publicKey: PermissionedDataJWTVerificationKey

    public init(
        authority: String,
        keyID: String = PermissionedDataJWT.spaceCredentialKeyID,
        generation: UInt64,
        publicKey: P256.Signing.PublicKey
    ) throws {
        guard (try? AccountIdentifiers.validateDID(authority)) != nil,
              Self.isSpaceCredentialKeyID(keyID),
              generation > 0 else {
            throw SwanError.malformed("invalid pinned space credential key")
        }
        self.authority = authority
        self.keyID = keyID
        self.generation = generation
        self.publicKey = .p256(publicKey)
    }

    /// Pins the compressed (33-byte) or uncompressed (65-byte) secp256k1
    /// public material emitted by the pinned TypeScript PDS. Validation is
    /// local and does not parse a DID document or make a network request.
    public init(
        authority: String,
        keyID: String = PermissionedDataJWT.spaceCredentialKeyID,
        generation: UInt64,
        secp256k1PublicKey: Data
    ) throws {
        guard (try? AccountIdentifiers.validateDID(authority)) != nil,
              Self.isSpaceCredentialKeyID(keyID),
              generation > 0,
              PermissionedDataJWTVerificationKey
                .validatesSecp256k1PublicKey(secp256k1PublicKey) else {
            throw SwanError.malformed("invalid pinned secp256k1 space credential key")
        }
        self.authority = authority
        self.keyID = keyID
        self.generation = generation
        publicKey = .secp256k1PublicKey(secp256k1PublicKey)
    }

    private static func isSpaceCredentialKeyID(_ value: String) -> Bool {
        value == PermissionedDataJWT.spaceCredentialKeyID
            || value == PermissionedDataJWT.spaceCredentialFallbackKeyID
    }
}

public struct PinnedSpaceCredentialPublicKeyResolver:
    SpaceCredentialPublicKeyResolver
{
    private let keys: [PinnedKey: PermissionedDataJWTVerificationKey]

    public init(pins: [PinnedSpaceCredentialPublicKey]) throws {
        var selected: [PinnedKey: (generation: UInt64, key: PermissionedDataJWTVerificationKey)] = [:]
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
    ) async throws -> PermissionedDataJWTVerificationKey? {
        let exact = PinnedKey(authority: issuer, keyID: keyID)
        if let key = keys[exact] { return key }
        // A credential header normally names `#atproto_space`, but proposal
        // 0016 permits the ordinary account key if no dedicated method is
        // published. The pinned TypeScript PDS currently resolves exactly
        // this fallback for simplespace authorities.
        guard keyID == PermissionedDataJWT.spaceCredentialKeyID else {
            return nil
        }
        return keys[PinnedKey(
            authority: issuer,
            keyID: PermissionedDataJWT.spaceCredentialFallbackKeyID
        )]
    }

    private struct PinnedKey: Hashable, Sendable {
        let authority: String
        let keyID: String
    }
}

/// An immutable offline delegation-key pin for interop fixtures and explicitly
/// configured local peers. A pin never authorizes network resolution; it is
/// selected only after bounded inspection established the exact issuer and
/// `#atproto` key ID.
public struct PinnedSpaceDelegationPublicKey: Sendable {
    public let issuer: String
    public let keyID: String
    public let generation: UInt64
    let publicKey: PermissionedDataJWTVerificationKey

    public init(
        issuer: String,
        keyID: String = PermissionedDataJWT.delegationKeyID,
        generation: UInt64,
        publicKey: P256.Signing.PublicKey
    ) throws {
        guard (try? AccountIdentifiers.validateDID(issuer)) != nil,
              keyID == PermissionedDataJWT.delegationKeyID,
              generation > 0 else {
            throw SwanError.malformed("invalid pinned delegation key")
        }
        self.issuer = issuer
        self.keyID = keyID
        self.generation = generation
        self.publicKey = .p256(publicKey)
    }

    public init(
        issuer: String,
        keyID: String = PermissionedDataJWT.delegationKeyID,
        generation: UInt64,
        secp256k1PublicKey: Data
    ) throws {
        guard (try? AccountIdentifiers.validateDID(issuer)) != nil,
              keyID == PermissionedDataJWT.delegationKeyID,
              generation > 0,
              PermissionedDataJWTVerificationKey
                .validatesSecp256k1PublicKey(secp256k1PublicKey) else {
            throw SwanError.malformed("invalid pinned secp256k1 delegation key")
        }
        self.issuer = issuer
        self.keyID = keyID
        self.generation = generation
        publicKey = .secp256k1PublicKey(secp256k1PublicKey)
    }
}

public struct PinnedSpaceDelegationPublicKeyResolver:
    SpaceDelegationPublicKeyResolver
{
    private let keys: [PinnedKey: PermissionedDataJWTVerificationKey]

    public init(pins: [PinnedSpaceDelegationPublicKey]) throws {
        var selected: [PinnedKey: (generation: UInt64, key: PermissionedDataJWTVerificationKey)] = [:]
        for pin in pins {
            let identity = PinnedKey(issuer: pin.issuer, keyID: pin.keyID)
            if let existing = selected[identity] {
                guard existing.generation != pin.generation else {
                    throw SwanError.malformed("duplicate pinned delegation key generation")
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
    ) async throws -> PermissionedDataJWTVerificationKey? {
        keys[PinnedKey(issuer: issuer, keyID: keyID)]
    }

    private struct PinnedKey: Hashable, Sendable {
        let issuer: String
        let keyID: String
    }
}

/// Explicitly refuses remote authority resolution when no startup-bound
/// resolver has been configured. It never turns request input into a DID/PLC
/// or network lookup.
public struct UnavailableSpaceCredentialPublicKeyResolver:
    SpaceCredentialPublicKeyResolver
{
    public init() {}

    public func publicKey(
        for _: String,
        keyID _: String
    ) async throws -> PermissionedDataJWTVerificationKey? {
        nil
    }
}

/// Explicitly refuses remote user-key resolution for delegation exchange when
/// no startup-bound resolver has been configured. This prevents a bearer token
/// from becoming an SSRF or request-time DID/PLC lookup primitive.
public struct UnavailableSpaceDelegationPublicKeyResolver:
    SpaceDelegationPublicKeyResolver
{
    public init() {}

    public func publicKey(
        for _: String,
        keyID _: String
    ) async throws -> PermissionedDataJWTVerificationKey? {
        nil
    }
}

/// A client-attestation policy must distinguish its own rejection from a
/// durable policy or key-store failure so an HTTP adapter can render the
/// profile's `InvalidClientAttestation` error without exposing implementation
/// details. The enum carries no token, client, or metadata material.
public enum SpaceCredentialClientAttestationFailure:
    Error, Sendable, Equatable, CustomStringConvertible
{
    case invalid
    case unavailable

    public var description: String {
        switch self {
        case .invalid:
            "invalid client attestation"
        case .unavailable:
            "client attestation service unavailable"
        }
    }
}

/// Issues proposal-shaped space credentials after the authority's durable
/// policy has permitted the exact reader/app tuple. There is intentionally no
/// arbitrary `clientID` parameter: client identity enters only through the
/// separately verifiable attestation policy.
public struct DurableSpaceCredentialAuthority: SpaceCredentialAuthoritySigner {
    public struct Configuration: Sendable, Equatable {
        /// The default lifetime Swan *issues*, deliberately far below the
        /// proposal ceiling it *accepts*.
        ///
        /// A space credential carries no reader identity and is never
        /// re-checked against membership after it is minted, so its lifetime is
        /// the revocation window: a member removed from a space keeps reading
        /// until the credential it already holds expires. Five minutes bounds
        /// that window to something an operator can reason about while leaving
        /// the exchange cheap enough to repeat.
        ///
        /// This changes only what this authority mints.
        /// ``PermissionedDataJWT/spaceCredentialLifetime`` remains the two-hour
        /// interop ceiling, so credentials minted by another proposal-0016
        /// implementation are still accepted unchanged.
        public static let defaultLifetime: TimeInterval = 5 * 60

        public static let standard = Configuration(uncheckedLifetime: defaultLifetime)

        public let lifetime: TimeInterval

        public init(lifetime: TimeInterval = defaultLifetime) throws {
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
        // A credential never authorizes creation of another credential. The
        // only admissible requesters are a direct account principal (used by
        // non-HTTP authority control) or the narrow verifier-produced
        // delegation context. Both bind the user and exact space before the
        // durable policy transaction begins.
        let requesterMatches: Bool
        switch authorization {
        case let .accountOAuth(subject, _):
            requesterMatches = subject == user
        case let .spaceDelegation(subject, delegatedSpace):
            requesterMatches = subject == user && delegatedSpace == space
        default:
            requesterMatches = false
        }
        guard requesterMatches,
              (try? AccountIdentifiers.validateDID(user)) != nil else {
            throw SwanError.unauthorized("credential requester does not match the requested user")
        }
        let clientID: String?
        do {
            clientID = try await clientAttestationPolicy.verifiedClientID(
                for: clientAttestation,
                authority: space.authority,
                now: now
            )
        } catch let failure as SpaceCredentialClientAttestationFailure {
            throw failure
        } catch {
            throw SpaceCredentialClientAttestationFailure.unavailable
        }
        try await policyDirectory.authorizeSimpleSpaceCredentialRead(
            space: space,
            user: user,
            clientID: clientID,
            authorization: authorization
        )
        guard let signingKey = try await signingKeys.signingKey(for: space.authority),
              signingKey.authority == space.authority,
              signingKey.keyID == PermissionedDataJWT.spaceCredentialKeyID
                || signingKey.keyID == PermissionedDataJWT.spaceCredentialFallbackKeyID else {
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

/// Verifies bounded ES256 or ES256K user-to-space-host delegations through a
/// local or pinned key resolver. A separately injected durable replay store
/// consumes the verified JTI before policy or signing; this verifier itself
/// remains pure and never performs network resolution.
public struct DurableSpaceDelegationVerifier: SpaceDelegationAuthorizationVerifier {
    public struct Configuration: Sendable, Equatable {
        public static let standard = Configuration(uncheckedClockSkew: 60)

        public let clockSkew: TimeInterval

        public init(clockSkew: TimeInterval = 60) throws {
            guard (0 ... 5 * 60).contains(clockSkew) else {
                throw SwanError.malformed("invalid delegation clock skew")
            }
            self.clockSkew = clockSkew
        }

        private init(uncheckedClockSkew: TimeInterval) {
            clockSkew = uncheckedClockSkew
        }
    }

    private let publicKeys: any SpaceDelegationPublicKeyResolver
    private let configuration: Configuration

    public init(
        publicKeys: any SpaceDelegationPublicKeyResolver,
        configuration: Configuration = .standard
    ) {
        self.publicKeys = publicKeys
        self.configuration = configuration
    }

    public func verifiedDelegation(
        for token: String,
        expectedSpace: SpaceURI,
        now: Date = Date()
    ) async throws -> VerifiedSpaceDelegation {
        let inspection = try PermissionedDataJWT.inspectDelegationToken(token)
        let expectedAudience = "\(expectedSpace.authority)#atproto_space_host"
        guard inspection.claims.aud == expectedAudience,
              inspection.claims.sub == expectedSpace.rawValue else {
            throw SwanError.unauthorized("delegation token does not match the requested authority or space")
        }
        guard let publicKey = try await publicKeys.publicKey(
            for: inspection.claims.iss,
            keyID: inspection.header.kid ?? ""
        ) else {
            // Deliberately do not distinguish a missing local account, absent
            // pin, or disabled resolver to a remote bearer-token sender.
            throw SwanError.unavailable("delegation verification key is unavailable")
        }
        let claims = try PermissionedDataJWT.verifyDelegationToken(
            token,
            publicKey: publicKey,
            audience: expectedAudience,
            expectedSpace: expectedSpace,
            now: now,
            clockSkew: configuration.clockSkew
        )
        return VerifiedSpaceDelegation(
            authorization: .spaceDelegation(subject: claims.iss, space: expectedSpace),
            issuer: claims.iss,
            audience: claims.aud,
            space: expectedSpace,
            jti: claims.jti,
            expiresAt: Date(timeIntervalSince1970: TimeInterval(claims.exp))
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
        let publicKey: PermissionedDataJWTVerificationKey
        do {
            guard let resolved = try await publicKeys.publicKey(
                for: inspection.claims.iss,
                keyID: inspection.header.kid ?? ""
            ) else {
                // Do not attempt remote resolution from an auth path. The
                // caller cannot distinguish an absent remote key from a
                // disabled cache.
                throw SwanError.unavailable(
                    "space credential verification key is unavailable"
                )
            }
            publicKey = resolved
        } catch is SpaceCredentialPublicKeyResolutionError {
            // Preserve the local resolver's typed terminal signal inside the
            // composition layer while exposing only the pre-existing opaque
            // availability error to HTTP and other authorization callers.
            throw SwanError.unavailable(
                "space credential verification key is unavailable"
            )
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
