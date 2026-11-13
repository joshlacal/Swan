import ArgumentParser
import Crypto
import Foundation
import Logging
import Petrel
import PetrelCrypto
import PetrelPLC
import SwanAccountExport
@_spi(ServeStartup) import SwanAccounts
import SwanHTTP
import SwanInterop
import SwanCore
import SwanOAuth
import PetrelFirehose
import PetrelRepo
import SwanSQLite
import SwanStorage
import SwanSpaces
import ServiceLifecycle

private extension PermissionedRemoteReplicaIncrementalSyncOutcome {
    var code: String {
        switch self {
        case .applied: "applied"
        case .exactDuplicate: "exact_duplicate"
        case .unchanged: "unchanged"
        case .fullCARRecoveryRequired: "full_car_recovery_required"
        case .casConflict: "cas_conflict"
        case .conflictingReplay: "conflicting_replay"
        case .staleOrReordered: "stale_or_reordered"
        case .integrityFailure: "integrity_failure"
        }
    }

    var passed: Bool {
        switch self {
        case .applied, .exactDuplicate, .unchanged: true
        default: false
        }
    }
}

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
import SwanAccounts
#endif

/// Offline operator configuration for the notification laboratory. All key
/// pins are public verification material; outbound signing remains backed by
/// the separately configured encrypted account key store. Destinations are
/// static, peer-pinned facts rather than data learned from registrations.
struct ServeNotificationRuntime {
    let credentialPins: [PinnedSpaceCredentialPublicKey]
    let delegationPins: [PinnedSpaceDelegationPublicKey]
    let servicePins: [PinnedSpaceServicePublicKey]
    let credentialPublicKeys: PinnedSpaceCredentialPublicKeyResolver
    let remoteCredentialPublicKeys: (any SpaceCredentialPublicKeyResolver)?
    let remoteDelegationPublicKeys: (any SpaceDelegationPublicKeyResolver)?
    let delegationPublicKeys: PinnedSpaceDelegationPublicKeyResolver
    let servicePublicKeys: PinnedSpaceServicePublicKeyResolver
    let recipientBindings: SwanSpaceNotificationRecipientBindings
    let destinations: StaticSwanSpaceNotificationDestinations
    let peerPinnedTransportConfiguration: NIOPeerPinnedOAuthPostTransport.Configuration
    let managingServiceAudience: String?

    private struct Configuration: Decodable {
        let credentialPublicKeys: [CredentialKey]
        let delegationPublicKeys: [CredentialKey]?
        let servicePublicKeys: [ServiceKey]
        let authorityDestinations: [Destination]
        let registrationDestinations: [Destination]
        let recipientServiceBindings: [RecipientServiceBinding]?
        let managingServiceAudience: String?
        let credentialKeyPLC: CredentialKeyPLC?
        let delegationKeyPLC: DelegationKeyPLC?
    }

    static func kemBackfillPLCConfiguration(_ material: ValidatedStartupMaterial?) throws -> PLCClientConfiguration {
        guard let material else { return try .production() }
        let configuration = try JSONDecoder().decode(Configuration.self, from: material.rawData)
        let selection = configuration.credentialKeyPLC.map { ($0.origin, $0.laboratory, $0.allowlistedHost) }
            ?? configuration.delegationKeyPLC.map { ($0.origin, $0.laboratory, $0.allowlistedHost) }
        guard let selection, let origin = URL(string: selection.0) else { return try .production() }
        if selection.1 {
            guard let hostname = selection.2 else { throw ValidationError("KEM backfill laboratory PLC host is missing") }
            return try .laboratory(origin: origin, allowlistedHost: hostname)
        }
        return try .production(origin: origin)
    }

    private struct CredentialKeyPLC: Decodable {
        let origin: String
        let laboratory: Bool
        let allowlistedHost: String?
    }

    private struct DelegationKeyPLC: Decodable {
        let origin: String
        let laboratory: Bool
        let allowlistedHost: String?
        let allowedIssuers: [String]
    }

    private struct CredentialKey: Decodable {
        let issuer: String
        let keyID: String?
        let generation: UInt64
        let algorithm: String?
        let publicKey: String?
        let p256X963: String?
        let secp256k1: String?
    }

    private struct ServiceKey: Decodable {
        let issuer: String
        let generation: UInt64
        let algorithm: String?
        let publicKey: String?
        let p256X963: String?
        let secp256k1: String?
    }

    /// `key` is either an authority DID or an exact registered endpoint. The
    /// peer pin is required even though stock `serve` does not dispatch yet:
    /// this prevents an operator configuration from being mistaken for a
    /// complete delivery configuration without an explicit final-peer proof.
    private struct Destination: Decodable {
        let key: String
        let endpoint: String
        let audience: String
        let finalPeer: String
    }

    private struct RecipientServiceBinding: Decodable {
        let serviceIdentity: String
        let recipientAccount: String
    }

    private enum ConfigurationShapeError: Error {
        case invalid
    }

    /// Whether an operator-supplied notification configuration selects a
    /// laboratory PLC policy for either the credential or the delegation
    /// resolver.
    ///
    /// Decoded on its own, and deliberately non-throwing, so `serve`'s startup
    /// interlock can refuse a laboratory PLC on a public origin *before* any
    /// database, key store, or listener exists. A file this cannot read or
    /// decode answers `false`, which cannot widen anything: ``load(from:continuityStore:)``
    /// owns the diagnostics for an unusable file and refuses the same file a
    /// few lines later with a message that names the flag.
    static func selectsLaboratoryPLC(from data: Data) -> Bool {
        struct LaboratorySelection: Decodable {
            struct PLC: Decodable {
                let laboratory: Bool?
            }

            let credentialKeyPLC: PLC?
            let delegationKeyPLC: PLC?
        }
        guard data.count > 0, data.count <= 256 * 1_024,
              let selection = try? JSONDecoder()
              .decode(LaboratorySelection.self, from: data)
        else { return false }
        return (selection.credentialKeyPLC?.laboratory ?? false)
            || (selection.delegationKeyPLC?.laboratory ?? false)
    }
    static func selectsLaboratoryPLC(from url: URL) -> Bool {
        guard let data = try? readBoundedRegularFileNoFollow(
            url,
            maximumBytes: 256 * 1_024,
            validationMessage: "--notification-config is unavailable"
        ) else { return false }
        return selectsLaboratoryPLC(from: data)
    }
    static func load(
        from url: URL,
        continuityStore: any PLCCredentialKeyContinuityStore
    ) throws -> ServeNotificationRuntime {
        let data = try readBoundedRegularFileNoFollow(
            url,
            maximumBytes: 256 * 1_024,
            validationMessage: "--notification-config is unavailable"
        )
        return try load(from: data, continuityStore: continuityStore)
    }
    struct ValidatedStartupMaterial: Sendable {
        let rawData: Data
        let selectsLaboratoryPLC: Bool
    }

    /// Preflights and reads the notification configuration file once from disk
    /// through a bounded descriptor read, returning immutable startup material
    /// that cannot be mutated by later file swaps or link races.
    static func preflight(
        fromFile file: String?
    ) throws -> ValidatedStartupMaterial? {
        guard let file, !file.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return nil
        }
        let url = URL(fileURLWithPath: file)
        let data = try readBoundedRegularFileNoFollow(
            url,
            maximumBytes: 256 * 1_024,
            validationMessage: "--notification-config is unavailable"
        )
        guard data.count > 0, data.count <= 256 * 1_024 else {
            throw ValidationError("--notification-config has invalid size")
        }
        let lab = selectsLaboratoryPLC(from: data)
        return ValidatedStartupMaterial(rawData: data, selectsLaboratoryPLC: lab)
    }

    static func load(
        from data: Data,
        continuityStore: any PLCCredentialKeyContinuityStore
    ) throws -> ServeNotificationRuntime {
        guard data.count > 0, data.count <= 256 * 1_024 else {
            throw ValidationError("--notification-config has invalid size")
        }
        let configuration: Configuration
        do {
            try validateConfigurationShape(data)
            configuration = try JSONDecoder().decode(Configuration.self, from: data)
        } catch {
            throw ValidationError("--notification-config is invalid JSON")
        }
        do {
            let credentialPins = try configuration.credentialPublicKeys.map { pin in
                try credentialPin(pin)
            }
            let delegationPins = try (configuration.delegationPublicKeys ?? []).map { pin in
                try delegationPin(pin)
            }
            let servicePins = try configuration.servicePublicKeys.map { pin in
                try servicePin(pin)
            }
            let remoteCredentialPublicKeys: (any SpaceCredentialPublicKeyResolver)?
            if let plc = configuration.credentialKeyPLC {
                let allowedIssuers = Set(configuration.authorityDestinations.map(\.key))
                guard !allowedIssuers.isEmpty else {
                    throw SwanError.malformed("notification PLC requires an authority allowlist")
                }
                guard let origin = URL(string: plc.origin) else {
                    throw SwanError.malformed("notification PLC origin is invalid")
                }
                let plcConfiguration: PLCClientConfiguration
                if plc.laboratory {
                    plcConfiguration = try PLCClientConfiguration.laboratory(
                        origin: origin,
                        allowlistedHost: plc.allowlistedHost
                    )
                } else {
                    guard plc.allowlistedHost == nil else {
                        throw SwanError.malformed("production notification PLC cannot use a host allowlist")
                    }
                    plcConfiguration = try PLCClientConfiguration.production(origin: origin)
                }
                remoteCredentialPublicKeys = try PLCSpaceCredentialPublicKeyResolver(
                    configuration: plcConfiguration,
                    continuityStore: continuityStore,
                    allowedIssuers: allowedIssuers
                )
            } else {
                remoteCredentialPublicKeys = nil
            }
            let remoteDelegationPublicKeys: (any SpaceDelegationPublicKeyResolver)?
            if let plc = configuration.delegationKeyPLC {
                let allowedIssuers = Set(plc.allowedIssuers)
                guard !allowedIssuers.isEmpty,
                      allowedIssuers.count == plc.allowedIssuers.count,
                      allowedIssuers.allSatisfy({
                          (try? AccountIdentifiers.validateDID($0)) != nil
                      }) else {
                    throw SwanError.malformed(
                        "notification delegation PLC issuer allowlist is invalid"
                    )
                }
                guard let origin = URL(string: plc.origin) else {
                    throw SwanError.malformed(
                        "notification delegation PLC origin is invalid"
                    )
                }
                let plcConfiguration: PLCClientConfiguration
                if plc.laboratory {
                    plcConfiguration = try PLCClientConfiguration.laboratory(
                        origin: origin,
                        allowlistedHost: plc.allowlistedHost
                    )
                } else {
                    guard plc.allowlistedHost == nil else {
                        throw SwanError.malformed(
                            "production notification delegation PLC cannot use a host allowlist"
                        )
                    }
                    plcConfiguration = try PLCClientConfiguration.production(
                        origin: origin
                    )
                }
                remoteDelegationPublicKeys = try PLCSpaceCredentialPublicKeyResolver(
                    configuration: plcConfiguration,
                    continuityStore: continuityStore,
                    allowedIssuers: allowedIssuers
                )
            } else {
                remoteDelegationPublicKeys = nil
            }
            var authorities: [String: SwanSpaceNotificationDestination] = [:]
            var registrations: [String: SwanSpaceNotificationDestination] = [:]
            var peers: [String: OAuthIPAddress] = [:]
            for destination in configuration.authorityDestinations {
                let decoded = try decode(destination: destination, authorityKey: true)
                guard authorities[destination.key] == nil else {
                    throw SwanError.malformed("duplicate notification authority destination")
                }
                authorities[destination.key] = decoded.destination
                try insertPeer(decoded.peer, for: decoded.destination.endpoint, into: &peers)
            }
            for destination in configuration.registrationDestinations {
                let decoded = try decode(destination: destination, authorityKey: false)
                guard registrations[destination.key] == nil else {
                    throw SwanError.malformed("duplicate notification registration destination")
                }
                registrations[destination.key] = decoded.destination
                try insertPeer(decoded.peer, for: decoded.destination.endpoint, into: &peers)
            }
            var recipientAccounts: [String: String] = [:]
            for binding in configuration.recipientServiceBindings ?? [] {
                guard recipientAccounts[binding.serviceIdentity] == nil else {
                    throw SwanError.malformed("duplicate notification recipient service identity")
                }
                recipientAccounts[binding.serviceIdentity] = binding.recipientAccount
            }
            let recipientBindings = try SwanSpaceNotificationRecipientBindings(
                bindings: recipientAccounts
            )
            let managedAudience = try resolveManagingServiceAudience(
                requested: configuration.managingServiceAudience
            )
            return ServeNotificationRuntime(
                credentialPins: credentialPins,
                delegationPins: delegationPins,
                servicePins: servicePins,
                credentialPublicKeys: try PinnedSpaceCredentialPublicKeyResolver(
                    pins: credentialPins
                ),
                remoteCredentialPublicKeys: remoteCredentialPublicKeys,
                remoteDelegationPublicKeys: remoteDelegationPublicKeys,
                delegationPublicKeys: try PinnedSpaceDelegationPublicKeyResolver(
                    pins: delegationPins
                ),
                servicePublicKeys: try PinnedSpaceServicePublicKeyResolver(
                    pins: servicePins
                ),
                recipientBindings: recipientBindings,
                destinations: try StaticSwanSpaceNotificationDestinations(
                    authorityDestinations: authorities,
                    registrationDestinations: registrations
                ),
                peerPinnedTransportConfiguration: try .init(endpointPeers: peers),
                managingServiceAudience: managedAudience
            )
        } catch {
            throw ValidationError("--notification-config contains invalid pinned notification material")
        }
    }

    private static func validateConfigurationShape(_ data: Data) throws {
        let value = try JSONSerialization.jsonObject(with: data)
        guard let configuration = value as? [String: Any] else {
            throw ConfigurationShapeError.invalid
        }
        try rejectUnknownKeys(
            in: configuration,
            allowed: [
                "credentialPublicKeys",
                "delegationPublicKeys",
                "servicePublicKeys",
                "authorityDestinations",
                "registrationDestinations",
                "recipientServiceBindings",
                "managingServiceAudience",
                "credentialKeyPLC",
                "delegationKeyPLC",
            ]
        )
        try validateObjectArray(
            configuration["credentialPublicKeys"],
            allowed: [
                "issuer",
                "keyID",
                "generation",
                "algorithm",
                "publicKey",
                "p256X963",
                "secp256k1",
            ]
        )
        try validateObjectArray(
            configuration["delegationPublicKeys"],
            allowed: [
                "issuer",
                "keyID",
                "generation",
                "algorithm",
                "publicKey",
                "p256X963",
                "secp256k1",
            ]
        )
        try validateObjectArray(
            configuration["servicePublicKeys"],
            allowed: [
                "issuer",
                "generation",
                "algorithm",
                "publicKey",
                "p256X963",
                "secp256k1",
            ]
        )
        try validateObjectArray(
            configuration["authorityDestinations"],
            allowed: ["key", "endpoint", "audience", "finalPeer"]
        )
        try validateObjectArray(
            configuration["registrationDestinations"],
            allowed: ["key", "endpoint", "audience", "finalPeer"]
        )
        try validateObjectArray(
            configuration["recipientServiceBindings"],
            allowed: ["serviceIdentity", "recipientAccount"]
        )
        if let plc = configuration["credentialKeyPLC"] {
            guard let plc = plc as? [String: Any] else {
                throw ConfigurationShapeError.invalid
            }
            try rejectUnknownKeys(
                in: plc,
                allowed: ["origin", "laboratory", "allowlistedHost"]
            )
        }
        if let plc = configuration["delegationKeyPLC"] {
            guard let plc = plc as? [String: Any] else {
                throw ConfigurationShapeError.invalid
            }
            try rejectUnknownKeys(
                in: plc,
                allowed: [
                    "origin",
                    "laboratory",
                    "allowlistedHost",
                    "allowedIssuers",
                ]
            )
            guard let issuers = plc["allowedIssuers"] as? [Any],
                  !issuers.isEmpty,
                  issuers.count <= 1_024,
                  issuers.allSatisfy({ $0 is String }) else {
                throw ConfigurationShapeError.invalid
            }
        }
    }

    private static func validateObjectArray(
        _ value: Any?,
        allowed: Set<String>
    ) throws {
        guard let value else { return }
        guard let values = value as? [Any] else {
            throw ConfigurationShapeError.invalid
        }
        for value in values {
            guard let object = value as? [String: Any] else {
                throw ConfigurationShapeError.invalid
            }
            try rejectUnknownKeys(in: object, allowed: allowed)
        }
    }

    private static func rejectUnknownKeys(
        in object: [String: Any],
        allowed: Set<String>
    ) throws {
        guard Set(object.keys).isSubset(of: allowed) else {
            throw ConfigurationShapeError.invalid
        }
    }

    private static func resolveManagingServiceAudience(
        requested: String?
    ) throws -> String? {
        guard let requested else { return nil }
        let normalized = requested.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else {
            return nil
        }
        guard normalized.utf8.count <= 2_048,
              normalized.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            throw SwanError.malformed("notification managing service audience is invalid")
        }
        return normalized
    }

    private static func decode(
        destination: Destination,
        authorityKey: Bool
    ) throws -> (destination: SwanSpaceNotificationDestination, peer: OAuthIPAddress) {
        guard let url = URL(string: destination.endpoint),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              let host = components.host?.lowercased(),
              scheme == "https" || (scheme == "http" && host == "localhost") else {
            throw SwanError.malformed("notification endpoint is invalid")
        }
        let decodedDestination = try SwanSpaceNotificationDestination(
            endpoint: url,
            audience: destination.audience
        )
        guard let peer = OAuthIPAddress(literal: destination.finalPeer),
              (host == "localhost" ? peer.isLoopback : peer.isPublicInternetAddress) else {
            throw SwanError.malformed("notification final peer is invalid")
        }
        if authorityKey {
            guard (try? AccountIdentifiers.validateDID(destination.key)) != nil else {
                throw SwanError.malformed("notification authority key is invalid")
            }
        } else {
            guard destination.key.utf8.count <= 4_096,
                  URLComponents(string: destination.key)?.host != nil else {
                throw SwanError.malformed("notification registration key is invalid")
            }
        }
        return (decodedDestination, peer)
    }

    private static func insertPeer(
        _ peer: OAuthIPAddress,
        for endpoint: URL,
        into peers: inout [String: OAuthIPAddress]
    ) throws {
        if let existing = peers[endpoint.absoluteString], existing != peer {
            throw SwanError.malformed("notification endpoint has conflicting peer pins")
        }
        peers[endpoint.absoluteString] = peer
    }

    private static func credentialPin(_ pin: CredentialKey) throws -> PinnedSpaceCredentialPublicKey {
        let bytes = try keyBytes(
            algorithm: pin.algorithm,
            publicKey: pin.publicKey,
            p256X963: pin.p256X963,
            secp256k1: pin.secp256k1
        )
        switch bytes.algorithm {
        case .es256:
            return try .init(
                authority: pin.issuer,
                keyID: pin.keyID ?? PermissionedDataJWT.spaceCredentialIssuedKeyID,
                generation: pin.generation,
                publicKey: P256.Signing.PublicKey(x963Representation: bytes.value)
            )
        case .es256k:
            return try .init(
                authority: pin.issuer,
                keyID: pin.keyID ?? PermissionedDataJWT.spaceCredentialIssuedKeyID,
                generation: pin.generation,
                secp256k1PublicKey: bytes.value
            )
        }
    }

    private static func delegationPin(_ pin: CredentialKey) throws -> PinnedSpaceDelegationPublicKey {
        let bytes = try keyBytes(
            algorithm: pin.algorithm,
            publicKey: pin.publicKey,
            p256X963: pin.p256X963,
            secp256k1: pin.secp256k1
        )
        switch bytes.algorithm {
        case .es256:
            return try .init(
                issuer: pin.issuer,
                keyID: pin.keyID ?? PermissionedDataJWT.delegationKeyID,
                generation: pin.generation,
                publicKey: P256.Signing.PublicKey(x963Representation: bytes.value)
            )
        case .es256k:
            return try .init(
                issuer: pin.issuer,
                keyID: pin.keyID ?? PermissionedDataJWT.delegationKeyID,
                generation: pin.generation,
                secp256k1PublicKey: bytes.value
            )
        }
    }

    private static func servicePin(_ pin: ServiceKey) throws -> PinnedSpaceServicePublicKey {
        let bytes = try keyBytes(
            algorithm: pin.algorithm,
            publicKey: pin.publicKey,
            p256X963: pin.p256X963,
            secp256k1: pin.secp256k1
        )
        switch bytes.algorithm {
        case .es256:
            return try .init(
                issuer: pin.issuer,
                generation: pin.generation,
                publicKey: P256.Signing.PublicKey(x963Representation: bytes.value)
            )
        case .es256k:
            return try .init(
                issuer: pin.issuer,
                generation: pin.generation,
                secp256k1PublicKey: bytes.value
            )
        }
    }

    private enum PinnedKeyAlgorithm {
        case es256
        case es256k
    }

    private static func keyBytes(
        algorithm: String?,
        publicKey: String?,
        p256X963: String?,
        secp256k1: String?
    ) throws -> (algorithm: PinnedKeyAlgorithm, value: Data) {
        let selected: (PinnedKeyAlgorithm, String)
        switch algorithm?.uppercased() {
        case nil:
            switch (p256X963, secp256k1, publicKey) {
            case let (.some(value), nil, nil): selected = (.es256, value)
            case let (nil, .some(value), nil): selected = (.es256k, value)
            default: throw SwanError.malformed("notification key algorithm is ambiguous")
            }
        case "ES256":
            guard let value = publicKey ?? p256X963,
                  secp256k1 == nil else { throw SwanError.malformed("notification ES256 key is invalid") }
            selected = (.es256, value)
        case "ES256K":
            guard let value = publicKey ?? secp256k1,
                  p256X963 == nil else { throw SwanError.malformed("notification ES256K key is invalid") }
            selected = (.es256k, value)
        default:
            throw SwanError.malformed("notification key algorithm is unsupported")
        }
        guard let decoded = Data(base64URLEncoded: selected.1),
              (1 ... 128).contains(decoded.count) else {
            throw SwanError.malformed("notification public key is invalid")
        }
        return (selected.0, decoded)
    }
}

private struct ServePublicMutationDirectory: PublicRepositoryMutationDirectory {
    let directory: SQLitePreMigratedAccountDirectory
    let controls: SQLiteControlDatabase

    func publicRepositoryMutationTarget(selector: String) async throws -> PublicRepositoryMutationTarget? {
        let account: AccountControlAccount?
        if (try? AccountIdentifiers.validateDID(selector)) != nil {
            account = try await controls.account(did: selector)
        } else if let handle = try? AccountIdentifiers.canonicalHandle(selector) {
            account = try await controls.account(canonicalHandle: handle)
        } else {
            account = nil
        }
        guard let account else { return nil }
        // The store is keyed by the resolved DID, not by the caller's handle.
        guard let resolvedStore = await directory
            .generationRefreshingPublicMutationStore(
                did: account.did,
                firehoseFence: PublicFirehoseCommitFence(control: controls)
            ) else {
            return nil
        }
        return try PublicRepositoryMutationTarget(did: account.did, status: account.status, store: resolvedStore)
    }
}

private struct ServeManagementLiveAccountChecker: SwanManagementLiveAccountChecking {
    let directory: SQLitePreMigratedAccountDirectory

    func containsLiveAccount(did: String) async throws -> Bool {
        try await directory.publicFirehoseAccountDatabases().contains { account in
            account.did == did
        }
    }
}

private struct ServePublicMutationSignerProvider: PublicRepositoryMutationSignerProvider {
    let accounts: DurableAccountDirectory
    let keyStore: any AccountKeyStore

    func signer(for did: String) async throws -> PublicRepositoryMutationSigner {
        guard let account = try await accounts.account(did: did), account.status.authorizesAccount,
              let references = try await accounts.keyReferences(did: did) else {
            throw SwanError.unauthorized("public repository signer is unavailable")
        }
        let material = try await keyStore.key(for: references.signing)
        return PublicRepositoryMutationSigner(
            generation: references.signing.generation,
            signer: P256PublicRepositoryCommitSigner(
                privateKey: try P256.Signing.PrivateKey(rawRepresentation: material)
            )
        )
    }
}

/// Startup-only key projection for public repository mutations. This is kept
/// separate from `ServeLocalSpaceRuntime` so enabling public writes never
/// implicitly enables permissioned-space credentials, delegation, or sync.
struct ServePublicMutationRuntime {
    let signerProvider: any PublicRepositoryMutationSignerProvider

    static func make(
        keyDirectory: URL,
        kekFile: URL,
        kekID: String,
        controlStore: SQLiteControlDatabase
    ) async throws -> ServePublicMutationRuntime {
        let configuration = try AccountProvisioningSecrets
            .requiredMountedAccountKeyConfiguration(
                activeKeyID: kekID,
                secretFile: kekFile
            )
        let keyStore = try withExistingOwnerOnlyKeyDirectory(keyDirectory) {
            descriptor in
            try FileAccountKeyStore(
                existingRootDirectoryDescriptor: descriptor,
                configuration: configuration
            )
        }
        let hasher = try LibsodiumArgon2idHasher()
        let accounts = DurableAccountDirectory(
            store: controlStore,
            passwordHasher: hasher,
            verificationExecutor: try Argon2idVerificationExecutor(hasher: hasher)
        )
        let activeDIDs = try await controlStore.activeAccountDIDs()
        guard !activeDIDs.isEmpty else {
            throw SwanError.unavailable("public mutation runtime has no active accounts")
        }
        for did in activeDIDs {
            guard let references = try await accounts.keyReferences(did: did),
                  try await keyStore.publicKey(for: references.signing) != nil else {
                throw SwanError.unavailable("public mutation account keys are unavailable")
            }
        }
        return .init(
            signerProvider: ServePublicMutationSignerProvider(
                accounts: accounts,
                keyStore: keyStore
            )
        )
    }
}

private struct ServeUnavailableCredentialSigningKeyResolver:
    SpaceCredentialSigningKeyResolver
{
    func signingKey(for _: String) async throws -> SpaceCredentialAuthoritySigningKey? {
        nil
    }
}

/// Startup-only composition for Swan's local permissioned-space laboratory.
///
/// This is deliberately kept in the executable rather than exported from an
/// HTTP or account module: it is operator-selected deployment wiring, not a
/// capability handlers may construct from request input.  The one
/// `FileAccountKeyStore` is retained only by fixed-purpose protocol adapters.
/// In particular, this type never hands a database, scalar, or general signing
/// closure to the HTTP layer.
struct ServeLocalSpaceRuntime {
    let accountKeyStore: any AccountKeyStore
    let credentialSigningKeys: any SpaceCredentialSigningKeyResolver
    let credentialPublicKeys: any SpaceCredentialPublicKeyResolver
    let delegationPublicKeys: any SpaceDelegationPublicKeyResolver
    let servicePublicKeys: any SpaceServicePublicKeyResolver
    let credentialExchangeConfiguration: SwanSpaceCredentialHTTPConfiguration
    let delegationConfiguration: SwanSpaceDelegationHTTPConfiguration
    let repositorySyncConfiguration: SwanSpaceRepositorySyncHTTPConfiguration
    let repositoryCredentialConfiguration: SwanSpaceCredentialVerificationHTTPConfiguration
    let notificationServiceIssuer: any SpaceServiceAuthenticationIssuer

    static func make(
        keyDirectory: URL,
        kekFile: URL,
        kekID: String,
        controlStore: SQLiteControlDatabase
    ) async throws -> ServeLocalSpaceRuntime {
        let configuration = try AccountProvisioningSecrets
            .requiredMountedAccountKeyConfiguration(
                activeKeyID: kekID,
                secretFile: kekFile
            )
        // Keep this preflight non-creating: `serve` must not create a key
        // directory merely because local interop was requested.
        let keyStore = try withExistingOwnerOnlyKeyDirectory(keyDirectory) {
            descriptor in
            try FileAccountKeyStore(
                existingRootDirectoryDescriptor: descriptor,
                configuration: configuration
            )
        }
        let hasher = try LibsodiumArgon2idHasher()
        let accounts = DurableAccountDirectory(
            store: controlStore,
            passwordHasher: hasher,
            verificationExecutor: try Argon2idVerificationExecutor(hasher: hasher)
        )

        // A live local runtime is meaningful only for provisioned accounts.
        // Verify the durable control references and authenticated public key
        // metadata without decrypting a private scalar at startup.
        let activeDIDs = try await controlStore.activeAccountDIDs()
        guard !activeDIDs.isEmpty else {
            throw SwanError.unavailable("local space runtime has no active accounts")
        }
        for did in activeDIDs {
            guard let references = try await accounts.keyReferences(did: did),
                  try await keyStore.publicKey(for: references.signing) != nil else {
                throw SwanError.unavailable("local space runtime account keys are unavailable")
            }
        }
        let credentialSigningKeys = LocalAccountSpaceCredentialSigningKeyResolver(
            accounts: accounts,
            keyStore: keyStore
        )
        let credentialPublicKeys = LocalAccountSpaceCredentialPublicKeyResolver(
            accounts: accounts,
            publicKeyStore: keyStore
        )
        let delegationPublicKeys = LocalAccountSpaceDelegationPublicKeyResolver(
            accounts: accounts,
            publicKeyStore: keyStore
        )
        let servicePublicKeys = LocalAccountSpaceServicePublicKeyResolver(
            accounts: accounts,
            publicKeyStore: keyStore
        )
        let notificationServiceIssuer = LocalAccountSpaceServiceAuthenticationIssuer(
            accounts: accounts,
            keyStore: keyStore
        )
        return .init(
            accountKeyStore: keyStore,
            credentialSigningKeys: credentialSigningKeys,
            credentialPublicKeys: credentialPublicKeys,
            delegationPublicKeys: delegationPublicKeys,
            servicePublicKeys: servicePublicKeys,
            credentialExchangeConfiguration: .init(
                authoritySigningKeys: credentialSigningKeys,
                delegationPublicKeys: delegationPublicKeys,
                credentialPublicKeys: credentialPublicKeys
            ),
            delegationConfiguration: .init(
                tokenIssuer: LocalAccountSpaceDelegationTokenIssuer(
                    accounts: accounts,
                    keyStore: keyStore
                )
            ),
            repositorySyncConfiguration: .init(
                commitSigner: LocalAccountSpaceRepositoryCommitSigner(
                    accounts: accounts,
                    keyStore: keyStore
                )
            ),
            repositoryCredentialConfiguration: .init(
                credentialPublicKeys: credentialPublicKeys
            ),
            notificationServiceIssuer: notificationServiceIssuer
        )
    }
}

/// The complete permissioned-data capability assembly used by `swan serve`.
/// It is intentionally typed and startup-only: request handlers receive only
/// their fixed-purpose configurations and cannot add resolvers or open stores.
struct ServePermissionedRuntime {
    let credentialConfiguration: SwanSpaceCredentialHTTPConfiguration?
    let credentialExchangeConfiguration: SwanSpaceCredentialHTTPConfiguration?
    let delegationConfiguration: SwanSpaceDelegationHTTPConfiguration?
    let repositorySyncConfiguration: SwanSpaceRepositorySyncHTTPConfiguration?
    let repositoryCredentialConfiguration: SwanSpaceCredentialVerificationHTTPConfiguration?
    let notificationConfiguration: SwanSpaceNotificationHTTPConfiguration?
    let managedSpaceCheckAccessConfiguration: SwanManagedSpaceCheckAccessHTTPConfiguration?
    /// `--enable-spaces-open-interop`; `nil` keeps hardened behaviour.
    var spacesOpenInterop: SwanSpacesOpenInteropConfiguration? = nil

    static func compose(
        local: ServeLocalSpaceRuntime?,
        notification: ServeNotificationRuntime?,
        managingServiceAudience: String? = nil,
        clientAttestationPolicy: any SpaceCredentialClientAttestationPolicy =
            UnavailableSpaceCredentialClientAttestationPolicy(),
        serviceEndpointResolver: SwanServiceEndpointResolver? = nil,
        spacesOpenInterop: SwanSpacesOpenInteropConfiguration? = nil,
        openFederation: SwanDIDDocumentSpaceResolver? = nil
    ) async throws -> ServePermissionedRuntime {
        var credentialPublicKeys: (any SpaceCredentialPublicKeyResolver)?
        var delegationPublicKeys: (any SpaceDelegationPublicKeyResolver)?
        var servicePublicKeys: (any SpaceServicePublicKeyResolver)?

        switch (local, notification) {
        case let (.some(local), .some(notification)):
            credentialPublicKeys = try await CompositeSpaceCredentialPublicKeyResolver(
                local: local.credentialPublicKeys,
                remote: notification.remoteCredentialPublicKeys,
                pinned: notification.credentialPins
            )
            delegationPublicKeys = try await CompositeSpaceDelegationPublicKeyResolver(
                local: local.delegationPublicKeys,
                remote: notification.remoteDelegationPublicKeys,
                pinned: notification.delegationPins
            )
            servicePublicKeys = try await CompositeSpaceServicePublicKeyResolver(
                local: local.servicePublicKeys,
                pinned: notification.servicePins
            )
        case let (.some(local), nil):
            credentialPublicKeys = local.credentialPublicKeys
            delegationPublicKeys = local.delegationPublicKeys
            servicePublicKeys = local.servicePublicKeys
        case let (nil, .some(notification)):
            credentialPublicKeys = try await CompositeSpaceCredentialPublicKeyResolver(
                local: UnavailableSpaceCredentialPublicKeyResolver(),
                remote: notification.remoteCredentialPublicKeys,
                pinned: notification.credentialPins
            )
            delegationPublicKeys = try await CompositeSpaceDelegationPublicKeyResolver(
                local: UnavailableSpaceDelegationPublicKeyResolver(),
                remote: notification.remoteDelegationPublicKeys,
                pinned: notification.delegationPins
            )
            servicePublicKeys = notification.servicePublicKeys
        case (nil, nil):
            credentialPublicKeys = nil
            delegationPublicKeys = nil
            servicePublicKeys = nil
        }
        // `--enable-spaces-open-interop` (decision B(c)): after local, PLC,
        // and pinned sources have no answer, resolve any did:plc / did:web
        // issuer from its DID document. Only resolvers that already exist are
        // widened, so the flag never enables a route by itself.
        if let openFederation {
            credentialPublicKeys = credentialPublicKeys.map {
                FallbackSpaceCredentialPublicKeyResolver(primary: $0, fallback: openFederation)
            }
            delegationPublicKeys = delegationPublicKeys.map {
                FallbackSpaceDelegationPublicKeyResolver(primary: $0, fallback: openFederation)
            }
            servicePublicKeys = servicePublicKeys.map {
                FallbackSpaceServicePublicKeyResolver(primary: $0, fallback: openFederation)
            }
        }

        let registrationConfirmer: HTTPSwanSpaceRegistrationConfirmer?
        if local != nil {
            do {
                let pinned = notification?.peerPinnedTransportConfiguration
                let policy = try OAuthRemoteFetchPolicy(
                    allowLocalhostDevelopment: notification != nil
                )
                registrationConfirmer = HTTPSwanSpaceRegistrationConfirmer(
                    policy: policy,
                    transport: NIOPeerPinnedOAuthPostTransport(
                        configuration: try .init(
                            endpointPeers: pinned?.endpointPeers ?? [:],
                            allowsDynamicPeerSelection: true,
                            additionalTrustRootsPEM: pinned?.additionalTrustRootsPEM
                        )
                    )
                )
            } catch {
                throw SwanError.unavailable("space registration confirmer is unavailable")
            }
        } else {
            registrationConfirmer = nil
        }

        let credentialConfiguration: SwanSpaceCredentialHTTPConfiguration?
        if let credentialPublicKeys, let delegationPublicKeys {
            credentialConfiguration = .init(
                authoritySigningKeys: local?.credentialSigningKeys
                    ?? ServeUnavailableCredentialSigningKeyResolver(),
                delegationPublicKeys: delegationPublicKeys,
                credentialPublicKeys: credentialPublicKeys,
                registrationConfirmer: registrationConfirmer
            )
        } else {
            credentialConfiguration = nil
        }

        let notificationConfiguration: SwanSpaceNotificationHTTPConfiguration?
        let serviceAuthentication: (any SpaceServiceAuthenticationVerifier)?
        if let servicePublicKeys {
            let verifier = DurableSpaceServiceAuthenticationVerifier(
                publicKeys: servicePublicKeys
            )
            serviceAuthentication = verifier
            notificationConfiguration = .init(
                serviceAuthentication: verifier,
                recipientBindings: notification?.recipientBindings ?? .empty,
                serviceEndpointResolver: serviceEndpointResolver
            )
        } else {
            serviceAuthentication = nil
            notificationConfiguration = nil
        }

        let configuredManagingAudience: String?
        if let pinnedAudience = notification?.managingServiceAudience,
           let explicitAudience = managingServiceAudience {
            guard pinnedAudience == explicitAudience else {
                throw SwanError.malformed("managing service audience conflicts with notification configuration")
            }
            configuredManagingAudience = pinnedAudience
        } else {
            configuredManagingAudience = notification?.managingServiceAudience ?? managingServiceAudience
        }

        let managedSpaceCheckAccessConfiguration: SwanManagedSpaceCheckAccessHTTPConfiguration?
        if let serviceAuthentication,
           let managingServiceAudience = configuredManagingAudience {
            managedSpaceCheckAccessConfiguration = try .init(
                serviceAuthentication: serviceAuthentication,
                managingServiceAudience: managingServiceAudience
            )
        } else {
            managedSpaceCheckAccessConfiguration = nil
        }

        return .init(
            credentialConfiguration: credentialConfiguration,
            credentialExchangeConfiguration: local.map { local in
                .init(
                    authoritySigningKeys: local.credentialSigningKeys,
                    delegationPublicKeys: delegationPublicKeys
                        ?? UnavailableSpaceDelegationPublicKeyResolver(),
                    credentialPublicKeys: credentialPublicKeys
                        ?? UnavailableSpaceCredentialPublicKeyResolver(),
                    clientAttestationPolicy: clientAttestationPolicy,
                    registrationConfirmer: registrationConfirmer
                )
            },
            delegationConfiguration: local?.delegationConfiguration,
            repositorySyncConfiguration: local?.repositorySyncConfiguration,
            repositoryCredentialConfiguration: credentialPublicKeys.map {
                .init(credentialPublicKeys: $0)
            },
            notificationConfiguration: notificationConfiguration,
            managedSpaceCheckAccessConfiguration: managedSpaceCheckAccessConfiguration,
            spacesOpenInterop: spacesOpenInterop
        )
    }

    func makeServer(
        profile: ProtocolProfile,
        configuration: SwanHTTPConfiguration,
        oauthRuntime: SwanOAuthRuntime,
        directory: SQLitePreMigratedAccountDirectory,
        accountControlStore: SQLiteControlDatabase,
        localSpaceRuntime: ServeLocalSpaceRuntime? = nil,
        publicMutationRuntime: ServePublicMutationRuntime? = nil,
        localhostPARConfiguration: SwanLocalhostPARConfiguration? = nil,
        localhostOAuthConfiguration: SwanLocalhostOAuthConfiguration? = nil,
        authorizationServerConfiguration: SwanOAuthAuthorizationServerConfiguration? = nil,
        accountEmailXRPC: SwanAccountEmailXRPCServer? = nil,
        legacySessionXRPC: SwanLegacySessionXRPCServer? = nil,
        actorPreferencesXRPC: SwanActorPreferencesXRPCServer? = nil,
        accountPortalHTTP: SwanAccountPortalHTTP? = nil,
        accountLifecycleXRPC: SwanAccountLifecycleXRPCAdapter? = nil,
        didWebIdentityHTTP: SwanDidWebIdentityHTTP? = nil,
        xrpcPipethrough: SwanXRPCPipethroughServer? = nil,
        loginClientIdentityPolicy: SwanLoginClientIdentityPolicy = .direct,
        publicFirehoseStreaming: SwanPublicFirehoseStreamingRuntime? = nil,
        identityAdmission: (any SwanIdentityAdmissionEvaluating)? = nil,
        foreignHandleResolution: (any SwanForeignHandleResolving)? = nil,
        spaceCredentialPolicyDirectory: (any AuthorizedSimpleSpaceCredentialDirectory)? = nil,
        simpleSpaceLifecycleDirectory: (any AuthorizedSimpleSpaceLifecycleDirectory)? = nil,
        spaceNotificationDirectory: (any AuthorizedSpaceNotificationDirectory)? = nil,
        spaceCredentialIssuance: DurableSpaceCredentialAuthority.Configuration = .standard
    ) -> SwanHTTPServer {
        SwanHTTPServer(
            profile: profile,
            configuration: configuration,
            oauthRuntime: oauthRuntime,
            localhostPARConfiguration: localhostPARConfiguration,
            localhostOAuthConfiguration: localhostOAuthConfiguration,
            authorizationServerConfiguration: authorizationServerConfiguration,
            authenticatedGetSpaceDirectory: directory,
            accountControlStore: accountControlStore,
            spaceCredentialConfiguration: credentialConfiguration,
            spaceCredentialExchangeConfiguration: credentialExchangeConfiguration,
            spaceDelegationConfiguration: delegationConfiguration,
            spaceRepositorySyncConfiguration: repositorySyncConfiguration,
            spaceRepositoryCredentialConfiguration: repositoryCredentialConfiguration,
            spaceNotificationConfiguration: notificationConfiguration,
            managedSpaceCheckAccessConfiguration: managedSpaceCheckAccessConfiguration,
            spacesOpenInterop: spacesOpenInterop,
            publicRepositoryReadDirectory: directory,
            publicRepositoryMutationDirectory: publicMutationRuntime.map { _ in
                ServePublicMutationDirectory(directory: directory, controls: accountControlStore)
            },
            publicRepositoryMutationSignerProvider: publicMutationRuntime?.signerProvider,
            publicBlobSpoolAdmission: publicMutationRuntime.map { _ in
                directory.publicRepositorySpoolAdmission
            },
            blobStreamAdmission: directory.publicRepositorySpoolAdmission,
            accountEmailXRPC: accountEmailXRPC,
            legacySessionXRPC: legacySessionXRPC,
            accountPortalHTTP: accountPortalHTTP,
            accountLifecycleXRPC: accountLifecycleXRPC,
            didWebIdentityHTTP: didWebIdentityHTTP,
            actorPreferencesXRPC: actorPreferencesXRPC,
            xrpcPipethrough: xrpcPipethrough,
            loginClientIdentityPolicy: loginClientIdentityPolicy,
            publicFirehoseStreaming: publicFirehoseStreaming,
            identityAdmission: identityAdmission,
            foreignHandleResolution: foreignHandleResolution,
            spaceCredentialPolicyDirectory: spaceCredentialPolicyDirectory,
            simpleSpaceLifecycleDirectory: simpleSpaceLifecycleDirectory,
            spaceNotificationDirectory: spaceNotificationDirectory,
            spaceCredentialIssuance: spaceCredentialIssuance
        )
    }
}

/// Open and validate an existing owner-only key root exactly once. The
/// returned descriptor is borrowed by the caller and must be closed by that
/// caller; use `withExistingOwnerOnlyKeyDirectory` when constructing a store.
/// `O_NOFOLLOW` and `fstat` make the validation refer to the inode that will be
/// pinned, rather than to a later pathname lookup.
private func requireExistingOwnerOnlyKeyDirectory(_ url: URL) throws -> Int32 {
    let descriptor = url.withUnsafeFileSystemRepresentation { path in
        guard let path else { return Int32(-1) }
        return open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard descriptor >= 0 else {
        throw SwanError.unavailable("local space key directory is unavailable")
    }
    var status = stat()
    guard fstat(descriptor, &status) == 0,
          (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR),
          status.st_uid == geteuid(),
          Int(status.st_mode & mode_t(0o777)) == 0o700 else {
        _ = close(descriptor)
        throw SwanError.unavailable("local space key directory is unavailable")
    }
    return descriptor
}

/// Run a startup construction step against a validated, pinned key-root
/// descriptor. `FileAccountKeyStore` duplicates the descriptor before this
/// closure returns, so the borrowed descriptor is always closed here even
/// when construction fails.
private func withExistingOwnerOnlyKeyDirectory<Result>(
    _ url: URL,
    _ body: (Int32) throws -> Result
) throws -> Result {
    let descriptor = try requireExistingOwnerOnlyKeyDirectory(url)
    defer { _ = close(descriptor) }
    return try body(descriptor)
}

private func decodeBase64URLOAuthServerKey(_ value: Data) throws -> Data {
    var normalized = value
    if normalized.last == 0x0A {
        normalized.removeLast()
        if normalized.last == 0x0D {
            normalized.removeLast()
        }
    }
    guard let base64 = String(data: normalized, encoding: .utf8) else {
        throw ValidationError("oauth-server-key is invalid")
    }
    guard !normalized.isEmpty,
          normalized.count <= 256,
          let key = Data(base64URLEncoded: base64),
          key.count == 32 else {
        throw ValidationError("oauth-server-key is invalid")
    }
    return key
}

func readBoundedRegularFileNoFollow(
    _ url: URL,
    maximumBytes: Int,
    requireOwnerOnly: Bool = false,
    validationMessage: String
) throws -> Data {
    guard maximumBytes > 0 else { throw ValidationError(validationMessage) }
    let descriptor = url.withUnsafeFileSystemRepresentation { path in
        guard let path else { return Int32(-1) }
        return open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
    }
    guard descriptor >= 0 else { throw ValidationError(validationMessage) }
    defer { _ = close(descriptor) }

    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
          (metadata.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
          (!requireOwnerOnly || (metadata.st_uid == geteuid() && (metadata.st_mode & (S_IRWXG | S_IRWXO)) == 0)),
          metadata.st_size > 0,
          metadata.st_size <= off_t(maximumBytes) else {
        throw ValidationError(validationMessage)
    }

    let flags = fcntl(descriptor, F_GETFL)
    if flags >= 0 {
        _ = fcntl(descriptor, F_SETFL, flags & ~O_NONBLOCK)
    }

    var data = Data()
    data.reserveCapacity(min(Int(metadata.st_size), maximumBytes))
    var buffer = [UInt8](repeating: 0, count: min(64 * 1_024, maximumBytes + 1))
    while data.count <= maximumBytes {
        let allowed = min(buffer.count, maximumBytes + 1 - data.count)
        let count = buffer.withUnsafeMutableBytes { bytes -> Int in
            while true {
                #if canImport(Darwin)
                let result = Darwin.read(descriptor, bytes.baseAddress!, allowed)
                #else
                let result = Glibc.read(descriptor, bytes.baseAddress!, allowed)
                #endif
                if result < 0, errno == EINTR { continue }
                return result
            }
        }
        guard count >= 0 else { throw ValidationError(validationMessage) }
        if count == 0 { break }
        data.append(contentsOf: buffer.prefix(count))
    }
    guard !data.isEmpty, data.count <= maximumBytes else {
        throw ValidationError(validationMessage)
    }
    return data
}

private func readOAuthServerKeyFile(_ url: URL) throws -> Data {
    let raw = try readBoundedRegularFileNoFollow(
        url,
        maximumBytes: 258,
        requireOwnerOnly: true,
        validationMessage: "oauth-server-key file is unavailable"
    )
    return try decodeBase64URLOAuthServerKey(raw)
}

private func readOwnerOnlySecretFile(
    _ url: URL,
    maximumBytes: Int = 4 * 1_024,
    validationMessage: String
) throws -> String {
    let data = try readBoundedRegularFileNoFollow(
        url,
        maximumBytes: maximumBytes + 2,
        requireOwnerOnly: true,
        validationMessage: validationMessage
    )
    var normalized = data
    if normalized.last == 0x0A {
        normalized.removeLast()
        if normalized.last == 0x0D {
            normalized.removeLast()
        }
    }
    guard !normalized.isEmpty,
          !normalized.contains(0),
          let string = String(data: normalized, encoding: .utf8) else {
        throw ValidationError(validationMessage)
    }
    return string
}

struct RelayVerifierManifest: Decodable {
    let did: String
    let frameFiles: [String]
    let finalCARFile: String
    let finalRevision: String
    let finalCommitCID: String
    let finalDataCID: String
    let reconnects: [RelayReconnectEvidence]
    let getRepo: RelayGetRepoObservation
    let offlineSequenceStart: Int64?
    let offlineSequenceEnd: Int64?

    var expectedOfflineCommitCount: Int { 5 }

    var offlineSequenceRange: ClosedRange<Int64>? {
        guard let start = offlineSequenceStart, let end = offlineSequenceEnd else {
            return nil
        }
        return start ... end
    }

    static func decode(_ data: Data) throws -> Self {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys).isSubset(of: [
                  "did", "frameFiles", "finalCARFile", "finalRevision",
                  "finalCommitCID", "finalDataCID", "reconnects", "getRepo",
                  "offlineSequenceStart", "offlineSequenceEnd",
              ]) else {
            throw RelayVerifierError.invalidCaptureManifest
        }
        let decoded: Self
        do {
            decoded = try JSONDecoder().decode(Self.self, from: data)
        } catch {
            throw RelayVerifierError.invalidCaptureManifest
        }
        guard (try? DID(didString: decoded.did)) != nil,
              !decoded.frameFiles.isEmpty,
              decoded.frameFiles.count <= 100_000,
              decoded.frameFiles.allSatisfy({ !$0.isEmpty }),
              !decoded.finalCARFile.isEmpty,
              !decoded.reconnects.isEmpty,
              let offlineStart = decoded.offlineSequenceStart,
              let offlineEnd = decoded.offlineSequenceEnd,
              offlineStart > 0,
              offlineStart <= FirehoseFrameLimits.maximumSequence - 4,
              offlineEnd == offlineStart + 4,
              decoded.reconnects.contains(where: {
                  $0.upstreamCursor >= 0 &&
                      $0.upstreamCursor <= FirehoseFrameLimits.maximumSequence &&
                      $0.firstDeliveredRelaySequence == offlineStart
              }) else {
            throw RelayVerifierError.invalidCaptureManifest
        }
        return decoded
    }

    func finalHead() throws -> RelayRepositoryHead {
        let commit: CID
        let data: CID
        do {
            commit = try CID.parse(finalCommitCID)
            data = try CID.parse(finalDataCID)
            try PublicRepositoryCID.validate(commit)
            try PublicRepositoryCID.validate(data)
            _ = try PublicRepositoryTID(finalRevision)
        } catch {
            throw RelayVerifierError.invalidCaptureManifest
        }
        return .init(
            did: did,
            revision: finalRevision,
            commitCID: commit,
            dataCID: data
        )
    }

    static func resolve(_ path: String, relativeTo base: URL) -> URL {
        if path.hasPrefix("/") {
            return URL(fileURLWithPath: path).standardizedFileURL
        }
        return base.appending(path: path).standardizedFileURL
    }
}

@main
struct SwanCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "swan",
        abstract: "Swift-native AT Protocol permissioned-data interoperability laboratory",
        subcommands: [
            Serve.self, Account.self, Export.self, Backup.self, Restore.self, Verify.self, Lab.self,
            Firehose.self,
        ],
        defaultSubcommand: Verify.self
    )
}

extension SwanCommand {
    struct Backup: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Write an authenticated encrypted operator account backup"
        )

        @Option(name: .long, help: "Required Swan data directory containing control.sqlite")
        var dataDirectory: String

        @Option(name: .long, help: "Active account DID to back up")
        var did: String

        @Option(name: .long, help: "New backup directory; an existing path is never overwritten")
        var outputDirectory: String

        @Option(name: .long, help: "Owner-only mounted operator-secret file")
        var operatorSecretFile: String

        @Option(name: .long, help: "Owner-only mounted account-KEK file")
        var accountKEKFile: String

        @Option(name: .long, help: "Owner-only mounted operator-backup key file")
        var backupKeyFile: String

        @Option(name: .customLong("account-kek-id"), help: "Active account-KEK identifier")
        var accountKEKID: String = "primary"

        @Option(name: .long, help: "Protected account key-envelope directory; defaults to <data-directory>/keys")
        var accountKeyDirectory: String?

        func run() async throws {
            var control: SQLiteControlDatabase?
            var accountDatabase: SQLiteAccountDatabase?
            do {
                // Authorization remains the first operation. It is inside the
                // backup error boundary so even its failures collapse to the
                // command's one safe error without probing another path.
                _ = try AccountCommandSupport.authorization(
                    secretFilePath: operatorSecretFile
                )
                guard !dataDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                      !did.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                      !outputDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                      !accountKEKFile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                      !backupKeyFile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                      !accountKEKID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                      accountKeyDirectory.map({
                          !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                      }) ?? true else {
                    throw SwanOperatorAccountBackupError.failed
                }
                let canonicalDID = try AccountIdentifiers.validateDID(did)
                let backupKey = try SwanOperatorBackupKey(
                    secretFile: URL(fileURLWithPath: backupKeyFile)
                )
                let keyConfiguration = try AccountProvisioningSecrets
                    .requiredMountedAccountKeyConfiguration(
                        activeKeyID: accountKEKID,
                        secretFile: URL(fileURLWithPath: accountKEKFile)
                    )
                let dataURL = URL(fileURLWithPath: dataDirectory).standardizedFileURL
                let outputURL = URL(fileURLWithPath: outputDirectory).standardizedFileURL
                let keyURL = accountKeyDirectory.map { URL(fileURLWithPath: $0) }
                    ?? dataURL.appending(path: "keys", directoryHint: .isDirectory)
                let destination = try SwanPortableExportDestination(outputURL)

                let openedControl = try await SQLiteControlDatabase(
                    dataDirectory: dataURL,
                    openMode: .existingPortableExportSource
                )
                control = openedControl
                guard let account = try await openedControl.account(did: canonicalDID),
                      account.status == .active,
                      account.signingKey != nil,
                      account.rotationKey != nil,
                      account.publicGenesisCommitCID != nil,
                      let credential = try await openedControl.credential(did: canonicalDID) else {
                    throw SwanOperatorAccountBackupError.failed
                }
                try await openedControl.close()
                control = nil

                let openedAccount = try await SQLiteAccountDatabase(
                    dataDirectory: dataURL,
                    did: canonicalDID,
                    openMode: .existingPortableExportSource
                )
                accountDatabase = openedAccount
                let keyReader = try ExistingFileAccountKeyReader(
                    root: keyURL,
                    configuration: keyConfiguration
                )
                let result = try await SwanOperatorAccountBackupExporter(
                    database: openedAccount,
                    keyReader: keyReader
                ).backup(
                    account: account,
                    credential: credential,
                    using: backupKey,
                    to: destination
                )
                try await openedAccount.close()
                accountDatabase = nil
                try AccountCommandSupport.write(result)
            } catch {
                try? await accountDatabase?.close()
                try? await control?.close()
                throw ValidationError("operator backup failed")
            }
        }
    }

    struct Firehose: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "firehose",
            abstract: "Operator tools for the durable public firehose",
            subcommands: [ForceSync.self, InspectRelayCAR.self, VerifyRelayCapture.self]
        )

        struct InspectRelayCAR: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "inspect-relay-car",
                abstract: "Structurally inspect an ephemeral final repository CAR"
            )

            @Option(name: .long, help: "Owner-controlled final repository CAR")
            var car: String

            func run() async throws {
                do {
                    let bytes = try readBoundedRegularFileNoFollow(
                        URL(fileURLWithPath: car).standardizedFileURL,
                        maximumBytes: PublicRepositoryLimits.standard.maximumCARBytes,
                        validationMessage: "relay CAR is unavailable"
                    )
                    let snapshot = try await RelayFullRepositoryVerifier.inspect(car: bytes)
                    try AccountCommandSupport.write(RelayCARInspectionView(snapshot: snapshot))
                } catch {
                    throw ValidationError("relay CAR inspection failed")
                }
            }
        }

        struct VerifyRelayCapture: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "verify-relay-capture",
                abstract: "Independently verify ephemeral relay frames and Swan repository state"
            )

            @Option(name: .long, help: "Owner-controlled JSON manifest naming ephemeral inputs")
            var manifest: String

            @Option(name: .customLong("plc-origin"), help: "Authenticated PLC directory origin")
            var plcOrigin: String

            @Flag(
                name: .customLong("plc-laboratory"),
                help: "Allow an explicitly loopback/allowlisted HTTP PLC origin for the lab"
            )
            var plcLaboratory = false

            @Option(
                name: .customLong("plc-laboratory-allowlisted-host"),
                help: "Explicit Docker/service DNS host allowed for --plc-laboratory"
            )
            var plcLaboratoryAllowlistedHost: String?

            mutating func validate() throws {
                _ = try plcConfiguration()
            }

            func run() async throws {
                do {
                    let manifestURL = URL(fileURLWithPath: manifest).standardizedFileURL
                    let rawManifest = try readBoundedRegularFileNoFollow(
                        manifestURL,
                        maximumBytes: 256 * 1_024,
                        validationMessage: "relay verifier manifest is unavailable"
                    )
                    let input = try RelayVerifierManifest.decode(rawManifest)
                    let resolver = try PLCPublicRepositoryCommitKeyResolver(
                        configuration: plcConfiguration()
                    )
                    let commitVerifier = try await resolver.resolveCommitVerifier(for: input.did)
                    let base = manifestURL.deletingLastPathComponent()
                    let events = try input.frameFiles.map { path in
                        let url = RelayVerifierManifest.resolve(path, relativeTo: base)
                        let frame = try readBoundedRegularFileNoFollow(
                            url,
                            maximumBytes: FirehoseFrameLimits.maximumFrameBytes + 1,
                            validationMessage: "relay frame input is unavailable"
                        )
                        return try RelayFrameDecoder.decode(frame)
                    }
                    try RelayLifecycleVerifier.verify(events: events, expectedDID: input.did)
                    let sequence = try RelaySequenceVerifier.verify(
                        events: events,
                        reconnects: input.reconnects,
                        offlineCommitRange: input.offlineSequenceRange,
                        expectedOfflineCommitCount: input.expectedOfflineCommitCount
                    )

                    let acceptedHeads = InMemoryRelayAcceptedHeadStorage()
                    var relayState: RelayRepositoryVerificationState?
                    for event in events {
                        switch event {
                        case let .sync(sync):
                            if let current = relayState {
                                relayState = try await current.synchronizing(
                                    sync,
                                    verifier: commitVerifier,
                                    storage: acceptedHeads
                                )
                            } else {
                                relayState = try await .activationSync(
                                    sync,
                                    verifier: commitVerifier,
                                    storage: acceptedHeads
                                )
                            }
                        case let .commit(commit):
                            guard let current = relayState else {
                                throw RelayVerifierError.lifecycleOrderMismatch
                            }
                            relayState = try await current.applying(
                                commit: commit,
                                verifier: commitVerifier,
                                    storage: acceptedHeads
                            )
                        case .identity, .account, .info:
                            break
                        case .error:
                            throw RelayVerifierError.invalidEventBody
                        }
                    }
                    guard let relayState else { throw RelayVerifierError.missingFinalRepository }

                    let finalCARURL = RelayVerifierManifest.resolve(
                        input.finalCARFile,
                        relativeTo: base
                    )
                    let finalCAR = try readBoundedRegularFileNoFollow(
                        finalCARURL,
                        maximumBytes: PublicRepositoryLimits.standard.maximumCARBytes,
                        validationMessage: "final Swan repository CAR is unavailable"
                    )
                    let finalHead = try input.finalHead()
                    let swanFinal = try await RelayFullRepositoryVerifier.verify(
                        car: finalCAR,
                        expected: finalHead,
                        verifier: commitVerifier,
                                    storage: acceptedHeads
                    )
                    try RelayFinalStateVerifier.verify(
                        relay: relayState.snapshot,
                        swan: swanFinal.snapshot
                    )
                    _ = try RelayGetRepoPolicy.verify(input.getRepo)

                    try AccountCommandSupport.write(RelayVerificationAggregate(
                        did: input.did,
                        firstSequence: sequence.firstSequence,
                        lastSequence: sequence.lastSequence,
                        frameCount: events.count,
                        finalRevision: swanFinal.snapshot.revision,
                        finalCommitCID: swanFinal.snapshot.commitCID.string,
                        finalDataCID: swanFinal.snapshot.dataCID.string,
                        projectionDigest: RelayRepositoryDigest.projection(
                            swanFinal.snapshot.records
                        ),
                        checks: [
                            .init(name: .canonicalFrames, outcome: .passed),
                            .init(name: .orderedLifecycle, outcome: .passed),
                            .init(name: .cursorRecovery, outcome: .passed),
                            .init(name: .repositoryCommits, outcome: .passed),
                            .init(name: .getRepoMode, outcome: .passed),
                            .init(name: .finalMSTEquality, outcome: .passed),
                        ]
                    ))
                } catch let error as RelayVerifierError {
                    throw ValidationError("relay verification failed: \(error.rawValue)")
                } catch is ValidationError {
                    throw ValidationError("relay verification failed: input unavailable")
                } catch {
                    throw ValidationError("relay verification failed")
                }
            }

            private func plcConfiguration() throws -> PLCClientConfiguration {
                guard let origin = URL(string: plcOrigin) else {
                    throw ValidationError("--plc-origin must be a URL")
                }
                do {
                    if plcLaboratory {
                        return try .laboratory(
                            origin: origin,
                            allowlistedHost: plcLaboratoryAllowlistedHost
                        )
                    }
                    guard plcLaboratoryAllowlistedHost == nil else {
                        throw ValidationError(
                            "--plc-laboratory-allowlisted-host requires --plc-laboratory"
                        )
                    }
                    return try .production(origin: origin)
                } catch let error as ValidationError {
                    throw error
                } catch {
                    throw ValidationError("--plc-origin is not an allowed PLC origin")
                }
            }
        }

        struct ForceSync: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "force-sync",
                abstract: "Enqueue a forced #sync announcing the account's current public repository head"
            )

            @Option(name: .customLong("data-directory"), help: "Swan data directory")
            var dataDirectory: String

            @Option(name: .long, help: "Account DID to announce")
            var did: String

            func run() async throws {
                guard !dataDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                      !did.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    throw ValidationError("data-directory and did are required")
                }
                let dataURL = URL(fileURLWithPath: dataDirectory).standardizedFileURL
                var control: SQLiteControlDatabase?
                var accountDatabase: SQLiteAccountDatabase?
                do {
                    let openedControl = try await SQLiteControlDatabase(dataDirectory: dataURL)
                    control = openedControl
                    guard let account = try await openedControl.account(did: did),
                          account.status.authorizesAccount else {
                        throw ValidationError("account is not active: \(did)")
                    }
                    let openedAccount = try await SQLiteAccountDatabase(
                        dataDirectory: dataURL,
                        did: did
                    )
                    accountDatabase = openedAccount
                    let emitter = SQLitePublicLifecycleEmitter(
                        control: openedControl,
                        accounts: SingleAccountFirehoseSource(
                            account: PublicFirehoseAccountDatabase(
                                did: did,
                                database: openedAccount
                            )
                        )
                    )
                    let requestUUID = UUID().uuidString.lowercased()
                    try await emitter.emitManualSync(did: did, requestUUID: requestUUID, now: Date())
                    try await openedAccount.close()
                    accountDatabase = nil
                    try await openedControl.close()
                    control = nil
                    print("enqueued forced #sync for \(did) (request \(requestUUID))")
                } catch {
                    try? await accountDatabase?.close()
                    try? await control?.close()
                    if error is ValidationError { throw error }
                    throw ValidationError("firehose force-sync failed")
                }
            }
        }
    }

    struct Restore: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract:
                "Stage a portable archive or atomically restore an encrypted operator backup"
        )

        @Option(
            name: .long,
            help: "Existing portable-staging root or absent encrypted-backup restore target"
        )
        var dataDirectory: String

        @Option(name: .long, help: "Portable archive or encrypted operator-backup directory")
        var inputDirectory: String

        @Option(name: .long, help: "Owner-only mounted operator-secret file")
        var operatorSecretFile: String

        @Option(
            name: .long,
            help: "Owner-only mounted 32-byte backup key; selects encrypted-backup restore"
        )
        var backupKeyFile: String?

        @Option(
            name: .long,
            help: "Owner-only mounted 32-byte active account KEK required in backup mode"
        )
        var accountKekFile: String?

        @Option(name: .long, help: "Active account KEK identifier (default: primary)")
        var accountKekId: String?

        func run() async throws {
            // Operator authority is resolved before either supplied directory
            // is validated, standardized, opened, or otherwise probed.
            _ = try AccountCommandSupport.authorization(
                secretFilePath: operatorSecretFile
            )
            guard !dataDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  !inputDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw ValidationError(
                    backupKeyFile == nil
                        ? "portable restore failed"
                        : "operator backup restore failed"
                )
            }
            if let backupKeyFile {
                guard let accountKekFile,
                      !backupKeyFile.trimmingCharacters(
                          in: .whitespacesAndNewlines
                      ).isEmpty,
                      !accountKekFile.trimmingCharacters(
                          in: .whitespacesAndNewlines
                      ).isEmpty else {
                    throw ValidationError("operator backup restore failed")
                }
                do {
                    let backupKey = try SwanOperatorBackupKey(
                        secretFile: URL(fileURLWithPath: backupKeyFile)
                    )
                    let accountKEK = try SwanOperatorAccountKEK(
                        secretFile: URL(fileURLWithPath: accountKekFile)
                    )
                    let result = try await SwanOperatorAccountRestorer().restore(
                        backupAt: URL(fileURLWithPath: inputDirectory),
                        using: backupKey,
                        accountKEK: accountKEK,
                        accountKEKID: accountKekId ?? "primary",
                        to: URL(fileURLWithPath: dataDirectory)
                    )
                    try AccountCommandSupport.write(result)
                    return
                } catch {
                    throw ValidationError("operator backup restore failed")
                }
            }
            guard accountKekFile == nil, accountKekId == nil else {
                throw ValidationError("portable restore failed")
            }
            do {
                let result = try await SwanPortableAccountRestoreStager().stage(
                    archiveAt: URL(fileURLWithPath: inputDirectory),
                    dataDirectory: URL(fileURLWithPath: dataDirectory)
                )
                try AccountCommandSupport.write(result)
            } catch {
                throw ValidationError("portable restore failed")
            }
        }
    }

    struct Export: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Write a checksummed portable logical export for one active account"
        )

        @Option(name: .long, help: "Required Swan data directory containing control.sqlite")
        var dataDirectory: String

        @Option(name: .long, help: "Active account DID to export")
        var did: String

        @Option(name: .long, help: "New archive directory; an existing path is never overwritten")
        var outputDirectory: String

        @Option(name: .long, help: "Owner-only mounted operator-secret file")
        var operatorSecretFile: String

        @Option(name: .long, help: "Owner-only mounted account-KEK file")
        var accountKEKFile: String

        @Option(name: .long, help: "Active account-KEK identifier")
        var accountKEKID: String = "primary"

        @Option(name: .long, help: "Protected account key-envelope directory; defaults to <data-directory>/keys")
        var accountKeyDirectory: String?

        func run() async throws {
            // Resolve operator authority before probing any account metadata or
            // account-database path.
            let authorization = try AccountCommandSupport.authorization(
                secretFilePath: operatorSecretFile
            )
            guard !dataDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  !outputDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  !accountKEKFile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  !accountKEKID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw ValidationError("portable export options must not be empty")
            }
            let canonicalDID: String
            let keyConfiguration: AccountKeyEncryptionConfiguration
            do {
                canonicalDID = try AccountIdentifiers.validateDID(did)
                keyConfiguration = try AccountProvisioningSecrets.requiredMountedAccountKeyConfiguration(
                    activeKeyID: accountKEKID,
                    secretFile: URL(fileURLWithPath: accountKEKFile)
                )
            } catch {
                throw ValidationError("portable export configuration is invalid")
            }

            let dataURL = URL(fileURLWithPath: dataDirectory).standardizedFileURL
            let outputURL = URL(fileURLWithPath: outputDirectory).standardizedFileURL
            let keyURL = accountKeyDirectory.map { URL(fileURLWithPath: $0) }
                ?? dataURL.appending(path: "keys", directoryHint: .isDirectory)
            // Pin and validate the destination before opening any component
            // that could create, migrate, recover, or otherwise mutate source
            // state.
            let destination: SwanPortableExportDestination
            do {
                destination = try SwanPortableExportDestination(outputURL)
            } catch {
                throw ValidationError("portable export failed")
            }
            var control: SQLiteControlDatabase?
            var accountDatabase: SQLiteAccountDatabase?
            do {
                let openedControl = try await SQLiteControlDatabase(
                    dataDirectory: dataURL,
                    openMode: .existingPortableExportSource
                )
                control = openedControl
                guard let account = try await openedControl.account(did: canonicalDID) else {
                    throw AccountOperatorError.unknownAccount
                }
                guard account.status == .active,
                      account.signingKey != nil,
                      account.publicGenesisCommitCID != nil else {
                    throw AccountOperatorError.accountInactive
                }
                try await openedControl.close()
                control = nil
                let openedAccount = try await SQLiteAccountDatabase(
                    dataDirectory: dataURL,
                    did: canonicalDID,
                    openMode: .existingPortableExportSource
                )
                accountDatabase = openedAccount
                let keyStore = try ExistingFileAccountKeyReader(
                    root: keyURL,
                    configuration: keyConfiguration
                )
                let exporter = try SwanPortableAccountExporter(
                    database: openedAccount,
                    keyStore: keyStore
                )
                let result = try await exporter.export(account: account, to: destination)
                try await openedAccount.close()
                accountDatabase = nil

                // The only source mutation occurs after a complete archive has
                // been installed and independently verified.
                let declarationControl = try await SQLiteControlDatabase(dataDirectory: dataURL)
                control = declarationControl
                do {
                    _ = try await AccountOperatorService(store: declarationControl).declareExport(
                        did: canonicalDID,
                        manifestReference: result.manifestSHA256,
                        authorization: authorization
                    )
                } catch {
                    try? await declarationControl.close()
                    control = nil
                    throw ValidationError(
                        "portable export was published but its digest declaration failed; "
                            + "retry only the declaration with 'swan account declare-export'"
                    )
                }
                try await declarationControl.close()
                control = nil
                try AccountCommandSupport.write(result)
            } catch {
                try? await accountDatabase?.close()
                try? await control?.close()
                if let error = error as? AccountOperatorError {
                    throw AccountCommandSupport.validationError(for: error)
                }
                if let error = error as? ValidationError {
                    throw error
                }
                throw ValidationError("portable export failed")
            }
        }
    }

    struct Serve: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Run Swan's Hummingbird server")

        @Option(name: .long, help: "Pinned protocol profile JSON")
        var profile: String = "Profiles/permissioned-data-0016-2026-11-12.json"

        @Option(name: .long, help: "Local authority DID for committed Labyrinth conversation membership policy")
        var conversationSpaceAuthority: String?
        @Option(name: .long, help: "Exact HTTPS MLS policy service origin; no automatic discovery")
        var conversationSpacePolicyURL: String?
        @Option(name: .long, help: "Service JWT audience of the MLS policy service")
        var conversationSpacePolicyAudience: String?
        @Option(name: .long, help: "Literal IP pin of the MLS policy service")
        var conversationSpacePolicyPeerIP: String?
        @Flag(name: .long, help: "Permit the configured localhost MLS policy origin for a disposable lab")
        var conversationSpacePolicyLaboratory = false

        /// The public route surface is a separate contract family from
        /// `--profile`, and gets a separate flag rather than a widened one.
        /// `ProtocolProfile` requires a `permissioned-data-` id plus the crypto
        /// suite, oplog retention, and proposal pin that only that family
        /// carries; teaching one flag to mean two families would mean loosening
        /// invariants that existing checks were written against, which is the
        /// exact shape that has produced silent surface changes here before.
        ///
        /// Deliberately optional, and deliberately not a path by default. The
        /// first version of this flag defaulted to
        /// `Profiles/public-data-testing-2026-07-27.json`, a working-directory
        /// relative path: the runtime container's `WORKDIR` is the data volume
        /// and carries no `Profiles/` directory, so every containerized
        /// `swan serve` refused to start before binding a listener. Omitting
        /// the flag now selects `SwanPublicRouteSurface.default` — the profile
        /// this build attests — with no filesystem access at all.
        ///
        /// The value may be either a registered profile id
        /// (`public-data-testing-2026-08-06`) or a path to a profile artifact.
        /// The id form exists so a deployment that does not mount `Profiles/`
        /// can still pin its surface explicitly.
        @Option(
            name: .customLong("public-profile"),
            help: """
            Public-data protocol profile selecting the public XRPC route \
            surface: either a registered profile id or a path to a profile \
            JSON. Omit to use this build's attested public profile.
            """
        )
        var publicProfile: String?

        @Option(name: .long)
        var host: String = "127.0.0.1"

        @Option(name: .long)
        var port: Int = 3000

        @Option(name: .long, help: "Public issuer URL")
        var publicURL: String?

        /// The public listener's connection budget, and — because
        /// ``PublicFirehoseSubscriberAdmission`` sizes itself as a quarter of
        /// it — the anonymous `subscribeRepos` reservation too.
        ///
        /// The runtime already reserved a share of this budget; there was
        /// simply no way to say what the budget was, so an operator under load
        /// had the 256-slot compiled-in default and nothing else. 256 stays the
        /// default so the flag changes nothing for anyone who does not pass it;
        /// at that value 64 slots are reserved for anonymous firehose
        /// subscribers and 192 remain permanently reachable for login, OAuth,
        /// public reads, and the relay's own reconnect.
        @Option(
            name: .customLong("max-connections"),
            help: "Maximum simultaneously accepted public listener connections (default: 256); a quarter is reserved for anonymous firehose subscribers"
        )
        var maxConnections: Int = 256

        @Flag(name: .long, help: "Enable only the localhost-development-client OAuth PAR bridge; requires an HTTPS public issuer")
        var enableLocalhostPAR = false

        @Flag(name: .customLong("enable-localhost-oauth"), help: "Enable the localhost-development-client PAR, browser authorization, token, refresh, and revocation bridge; requires an HTTPS public issuer")
        var enableLocalhostOAuth = false

        @Flag(name: .customLong("enable-oauth-authorization-server"), help: "Enable the complete remote/public and private_key_jwt OAuth authorization server; requires an HTTPS public issuer and durable account/password support")
        var enableOAuthAuthorizationServer = false

        @Flag(name: .customLong("oauth-allow-localhost-development-client"), help: "Permit only AT Protocol's exact http://localhost development client metadata exception in the complete OAuth server")
        var oauthAllowLocalhostDevelopmentClient = false

        /// §5.7.4 / §5.7.5. Off by default, and that default is a **recorded
        /// divergence** rather than a preference: without a resolver an
        /// `include:` grants nothing and a bare `space:<type>` materialises no
        /// write targets, both of which a conformant AS does differently. It is
        /// opt-in because turning it on adds DNS, a DID-document read and a CAR
        /// fetch to the PAR path, and changes what an already-registered scope
        /// string mints — neither is a change to make on an operator's behalf.
        @Flag(name: .customLong("enable-lexicon-resolution"), help: "Resolve include:<nsid> permission sets and bare space:<type> collection declarations from their authority's cryptographically proved repo record (spec §5.7.4); requires the complete OAuth authorization server")
        var enableLexiconResolution = false

        /// Opt-in because it is the only thing that makes an unauthenticated
        /// route reach the network. A reference PDS resolves foreign handles
        /// from its identity resolver, and without this every handle-to-DID
        /// lookup a client sends here for someone else's handle answers
        /// `InvalidRequest` — measured against bsky.app, which asks on every
        /// profile it opens. Resolution reuses the pinned TXT and
        /// `/.well-known/atproto-did` path that verifies did:web claims, so
        /// reserved TLDs and non-public addresses are refused before a lookup.
        @Flag(name: .customLong("enable-foreign-handle-resolution"), help: "Answer com.atproto.identity.resolveHandle for handles this host does not hold, using the pinned DNS TXT and /.well-known/atproto-did resolver")
        var enableForeignHandleResolution = false

        @Option(
            name: .customLong("oauth-server-key-file"),
            help: "Owner-only mounted file containing the URL-safe-base64 OAuth server key"
        )
        var oauthServerKeyFile: String?

        @Option(name: .customLong("oauth-allow-metadata-ip"), help: "Explicit literal IP allowlist for laboratory OAuth client metadata/JWKS retrieval; repeat for each address")
        var oauthMetadataAllowedIPs: [String] = []

        @Option(
            name: .customLong("login-trusted-proxy-peer"),
            help: "Exact literal IPv4/IPv6 socket peer trusted to replace X-Swan-Client-IP; repeat for each proxy"
        )
        var loginTrustedProxyPeers: [String] = []

        @Option(name: .long, help: "Reserved root for control/account databases and blobs")
        var dataDirectory: String = ".swan-data"

        @Option(
            name: .customLong("space-oplog-retention"),
            help: "Retained permissioned-repository operations per account (default: 10000)"
        )
        var spaceOplogRetention: Int = 10_000

        @Option(name: .long, help: "Enable the separate loopback-only management listener on this port")
        var managementPort: Int?

        @Option(name: .long, help: "Literal loopback address for management: 127.0.0.1 or ::1")
        var managementAddress: String = "127.0.0.1"

        @Option(name: .long, help: "Mounted operator-secret file for the enabled management listener")
        var managementOperatorSecretFile: String?

        @Flag(name: .customLong("enable-management-plc-provisioning"), help: "Enable authenticated PLC prepare/activate routes on the separate management listener")
        var enableManagementPLCProvisioning = false

        @Flag(name: .customLong("enable-management-permanent-deletion"), help: "Enable resumable PLC-tombstoning permanent deletion on the separate management listener")
        var enableManagementPermanentDeletion = false

        @Flag(name: .customLong("enable-management-firehose-sync"), help: "Enable authenticated in-process public firehose sync emission on the separate management listener")
        var enableManagementFirehoseSync = false

        @Option(name: .customLong("management-deletion-plc-origin"), help: "PLC directory origin used only for permanent deletion")
        var managementDeletionPLCOrigin: String?

        @Flag(name: .customLong("management-deletion-plc-laboratory"), help: "Select explicit PLC laboratory policy for permanent deletion")
        var managementDeletionPLCLaboratory = false

        @Option(name: .customLong("management-deletion-plc-laboratory-allowlisted-host"), help: "Explicit Docker/service DNS host allowed for the permanent-deletion PLC laboratory origin")
        var managementDeletionPLCLaboratoryAllowlistedHost: String?

        @Option(name: .customLong("management-deletion-plc-reference-compatibility"), help: "Pinned permanent-deletion PLC submit compatibility; only did-plc-server-0.0.1 is supported")
        var managementDeletionPLCReferenceCompatibility: String?

        @Option(name: .customLong("management-account-kek-file"), help: "Owner-only mounted account-KEK file for management PLC provisioning/deletion")
        var managementAccountKEKFile: String?

        @Option(name: .customLong("management-account-kek-id"), help: "Active account-KEK identifier for management PLC provisioning/deletion")
        var managementAccountKEKID: String?

        @Option(name: .customLong("management-account-key-directory"), help: "Protected account key-envelope directory for management PLC provisioning/deletion; defaults to <data-directory>/keys")
        var managementAccountKeyDirectory: String?

        @Option(name: .customLong("notification-config"), help: "Owner-supplied JSON with ES256/ES256K public pins, peer-pinned destinations, and receiver service-identity bindings")
        var notificationConfig: String?

        @Flag(name: .customLong("enable-notification-delivery"), help: "Enable durable peer-pinned writer notifications and deletion recovery delivery")
        var enableNotificationDelivery = false

        @Flag(
            name: .customLong("enable-public-firehose"),
            help: "Enable durable public firehose sequencing into firehose.sqlite and serve com.atproto.sync.subscribeRepos WebSocket streaming on the public listener. With the worker disabled, account-local outbox rows accumulate durably and drain once this flag is enabled."
        )
        var enablePublicFirehose = false

        @Option(
            name: .customLong("public-firehose-retention-age-hours"),
            help: "Maximum retained firehose age in hours (default: 72)"
        )
        var publicFirehoseRetentionAgeHours: Int64 = 72

        @Option(
            name: .customLong("public-firehose-retention-max-rows"),
            help: "Maximum retained firehose rows (default: 1000000)"
        )
        var publicFirehoseRetentionMaxRows: Int64 = 1_000_000

        @Option(
            name: .customLong("public-firehose-retention-max-bytes"),
            help: "Maximum retained firehose frame bytes (default: 1073741824)"
        )
        var publicFirehoseRetentionMaxBytes: Int64 = 1_073_741_824

        @Option(
            name: .customLong("public-firehose-retention-interval-seconds"),
            help: "Retention pruning interval in seconds (default: 60)"
        )
        var publicFirehoseRetentionIntervalSeconds: Int64 = 60

        @Option(name: .customLong("notification-account-kek-file"), help: "Owner-only mounted account-KEK file for notification signing")
        var notificationAccountKEKFile: String?

        @Option(name: .customLong("notification-account-kek-id"), help: "Active account-KEK identifier for notification signing (default: primary)")
        var notificationAccountKEKID: String?

        @Option(name: .customLong("notification-account-key-directory"), help: "Protected account key-envelope directory for notification signing; defaults to <data-directory>/keys")
        var notificationAccountKeyDirectory: String?

        @Flag(name: .customLong("enable-email-recovery"), help: "Enable durable account confirmation and password-recovery XRPC with the isolated Mailpit SMTP worker")
        var enableEmailRecovery = false

        @Option(name: .customLong("email-proof-key-file"), help: "Owner-only mounted base64url 32-byte HMAC key required by --enable-email-recovery")
        var emailProofKeyFile: String?

        /// Legacy (app-password) sessions.
        ///
        /// Off by default and gated behind an owner-only mounted key, because
        /// enabling it introduces the deployment's FIRST long-lived bearer
        /// credential. Every OAuth credential is sender-constrained — an access
        /// token is useless without proof of possession of the DPoP key — so a
        /// captured request cannot be replayed from another machine. An app
        /// password can. Scoping bounds what a stolen one reaches; it does not
        /// make a captured request unreplayable.
        ///
        /// Swan takes no secret from a process environment or a secret manager:
        /// the whole surface is owner-only mounted files, so this follows
        /// `--email-proof-key-file` exactly.
        @Flag(name: .customLong("enable-legacy-sessions"), help: "Enable com.atproto.server.createSession and the app-password family (introduces a bearer credential)")
        var enableLegacySessions = false

        @Option(name: .customLong("legacy-session-signing-key-file"), help: "Owner-only mounted base64url 32-byte HMAC key required by --enable-legacy-sessions")
        var legacySessionSigningKeyFile: String?

        @Option(
            name: .customLong("legacy-session-account-kek-file"),
            help: "Owner-only mounted account-KEK file for legacy-session service-JWT signing; --appview-proxy-account-kek-file may be reused when AppView proxying is enabled"
        )
        var legacySessionAccountKEKFile: String?

        @Option(
            name: .customLong("legacy-session-account-kek-id"),
            help: "Active account-KEK identifier for legacy-session service-JWT signing (default: primary)"
        )
        var legacySessionAccountKEKID: String?

        @Option(
            name: .customLong("legacy-session-account-key-directory"),
            help: "Existing owner-only account key-envelope directory for legacy-session service-JWT signing; defaults to <data-directory>/keys"
        )
        var legacySessionAccountKeyDirectory: String?

        @Option(name: .customLong("email-sender"), help: "Canonical sender mailbox for the Mailpit account-email worker")
        var emailSender: String?

        @Option(name: .customLong("email-smtp-host"), help: "Mailpit SMTP host (default: mailpit)")
        var emailSMTPHost: String?

        @Option(name: .customLong("email-smtp-port"), help: "Mailpit SMTP port (default: 1025)")
        var emailSMTPPort: Int?

        @Option(name: .customLong("email-worker-id"), help: "Stable durable lease owner for the account-email worker")
        var emailWorkerID: String?

        // MARK: Account program startup configuration (Task 2)

        @Flag(
            name: .customLong("enable-account-portal"),
            help: "Enable the static account portal and its /account/** API surface"
        )
        var enableAccountPortal = false

        @Option(
            name: .customLong("account-portal-directory"),
            help: "Directory containing the compiled account portal assets (container default: /usr/local/share/swan/account)"
        )
        var accountPortalDirectory: String?

        @Option(
            name: .customLong("signup-policy"),
            help: "Signup admission policy: closed, inviteRequired, or openProtected (default: closed)"
        )
        var signupPolicy: String?

        @Option(
            name: .customLong("turnstile-secret-file"),
            help: "Owner-only mounted Turnstile siteverify secret required by --signup-policy openProtected"
        )
        var turnstileSecretFile: String?

        @Option(
            name: .customLong("signup-secret-file"),
            help: "Owner-only mounted 32-byte base64url signup secret (email-proof/invite HMAC)"
        )
        var signupSecretFile: String?

        @Option(
            name: .customLong("signup-account-kek-file"),
            help: "Owner-only mounted account-KEK file for signup key provisioning"
        )
        var signupAccountKEKFile: String?

        @Option(
            name: .customLong("signup-account-kek-id"),
            help: "Active account-KEK identifier for signup key provisioning (default: primary)"
        )
        var signupAccountKEKID: String?

        @Option(
            name: .customLong("signup-account-key-directory"),
            help: "Protected account key-envelope directory for signup key provisioning; defaults to <data-directory>/keys"
        )
        var signupAccountKeyDirectory: String?

        @Option(
            name: .customLong("email-smtp-mode"),
            help: "Authenticated SMTP mode: startTLS, implicitTLS, or plaintextLab; omit to use the Mailpit laboratory default"
        )
        var emailSMTPMode: String?

        @Option(
            name: .customLong("email-smtp-username-file"),
            help: "Owner-only mounted SMTP username file required by startTLS and implicitTLS modes"
        )
        var emailSMTPUsernameFile: String?

        @Option(
            name: .customLong("email-smtp-password-file"),
            help: "Owner-only mounted SMTP password file required by startTLS and implicitTLS modes"
        )
        var emailSMTPPasswordFile: String?

        @Option(
            name: .customLong("email-smtp-mechanism"),
            help: "SMTP authentication mechanism: plain, login, or xoauth2 (required by startTLS and implicitTLS modes)"
        )
        var emailSMTPMechanism: String?

        @Option(
            name: .customLong("email-smtp-expected-hostname"),
            help: "TLS certificate hostname expected from the SMTP server (required by startTLS and implicitTLS modes)"
        )
        var emailSMTPExpectedHostname: String?

        @Option(
            name: .customLong("email-smtp-max-attempts"),
            help: "Bounded SMTP delivery attempts (default: 3)"
        )
        var emailSMTPMaxAttempts: Int?

        @Option(
            name: .customLong("did-web-revalidation-interval-seconds"),
            help: "did:web background revalidation interval in seconds (default: 3600)"
        )
        var didWebRevalidationIntervalSeconds: Int = 3600

        @Option(
            name: .customLong("did-web-revalidation-grace-seconds"),
            help: "did:web revalidation grace period in seconds (default: 86400)"
        )
        var didWebRevalidationGraceSeconds: Int = 86_400

        @Option(
            name: .customLong("did-web-signing-key-file"),
            help: "Owner-only mounted 32-byte base64url did:web reserved signing key"
        )
        var didWebSigningKeyFile: String?

        @Option(
            name: .customLong("managing-service-audience"),
            help: "Explicit service-JWT audience for com.atproto.managedspace.checkAccess"
        )
        var managingServiceAudience: String?

        @Flag(
            name: .customLong("enable-local-space-interop"),
            help: "Enable local account-key credential, delegation, and repository-sync interop."
        )
        var enableLocalSpaceInterop = false

        @Flag(
            name: .customLong("enable-spaces-open-interop"),
            help: "Opt into upstream atproto-spaces interop: open DID-document federation and upstream scope/legacy-session semantics. Off by default."
        )
        var enableSpacesOpenInterop = false

        @Flag(
            name: .customLong("enable-public-repository-mutations"),
            help: "Enable the separately composed OAuth-authorized public repository mutation capability."
        )
        var enablePublicRepositoryMutations = false

        @Option(
            name: .customLong("public-account-kek-file"),
            help: "Owner-only mounted account-KEK file required by --enable-public-repository-mutations"
        )
        var publicAccountKEKFile: String?

        @Option(
            name: .customLong("public-account-kek-id"),
            help: "Active account-KEK identifier for public repository mutations (default: primary)"
        )
        var publicAccountKEKID: String?

        @Option(
            name: .customLong("public-account-key-directory"),
            help: "Existing owner-only account key-envelope directory for public repository mutations; defaults to <data-directory>/keys"
        )
        var publicAccountKeyDirectory: String?

        @Option(
            name: .customLong("space-account-kek-file"),
            help: "Owner-only mounted account-KEK file required by --enable-local-space-interop"
        )
        var spaceAccountKEKFile: String?

        @Option(
            name: .customLong("space-account-kek-id"),
            help: "Active account-KEK identifier for local space interop (default: primary)"
        )
        var spaceAccountKEKID: String?

        @Option(
            name: .customLong("space-account-key-directory"),
            help: "Existing owner-only account key-envelope directory for local space interop; defaults to <data-directory>/keys"
        )
        var spaceAccountKeyDirectory: String?

        @Option(
            name: .customLong("appview-did"),
            help: "Service DID of the AppView unmatched app.bsky XRPC is proxied to (default: did:web:api.bsky.app)"
        )
        var appViewDID: String?

        @Option(
            name: .customLong("appview-url"),
            help: "HTTPS origin of the configured AppView (default: https://api.bsky.app)"
        )
        var appViewURL: String?

        @Option(
            name: .customLong("appview-service-fragment"),
            help: "DID document service fragment naming the configured AppView (default: bsky_appview)"
        )
        var appViewServiceFragment: String?

        @Flag(
            name: .customLong("disable-appview-proxy"),
            help: "Refuse every unmatched app.bsky XRPC locally instead of proxying it. Proxying is on out of the box."
        )
        var disableAppViewProxy = false

        @Option(
            name: .customLong("appview-proxy-account-kek-file"),
            help: "Owner-only mounted account-KEK file the AppView proxy uses to mint per-request service tokens. Without it the proxy cannot authenticate to any service and stays closed."
        )
        var appViewProxyAccountKEKFile: String?

        @Option(
            name: .customLong("appview-proxy-account-kek-id"),
            help: "Active account-KEK identifier for AppView proxy service tokens (default: primary)"
        )
        var appViewProxyAccountKEKID: String?

        @Option(
            name: .customLong("appview-proxy-account-key-directory"),
            help: "Existing owner-only account key-envelope directory for AppView proxy service tokens; defaults to <data-directory>/keys"
        )
        var appViewProxyAccountKeyDirectory: String?

        /// Turns `--public-profile` into the route surface the router will
        /// register, or into a startup refusal.
        ///
        /// `nil` — the flag omitted — is the *only* non-refusal branch that
        /// does no I/O, and it yields this build's attested public profile. It
        /// is not a fallback: nothing reaches it after a failed read or a
        /// rejected id, so a selector that cannot be honoured still stops the
        /// process.
        ///
        /// A selector that names a file is read; a selector that names an id is
        /// looked up directly, so a deployment with no `Profiles/` directory
        /// mounted can still pin its surface. The two forms are distinguished
        /// syntactically rather than by trying one and falling back to the
        /// other: a fallback would report "unreadable file" for a misspelled id
        /// and hide which of the two the operator got wrong.
        ///
        /// There is deliberately no default-on-failure branch. A profile this
        /// build has no descriptor registry for cannot be served honestly:
        /// registering some other profile's method set would leave the process
        /// advertising one contract in `describeServer` and answering another,
        /// which is worse than not booting and is invisible from the outside.
        static func resolvePublicRouteSurface(
            selector: String?
        ) throws -> SwanPublicRouteSurface {
            guard let selector else { return .default }
            do {
                guard Self.isProfilePath(selector) else {
                    guard let surface = SwanPublicRouteSurface(
                        profileID: selector
                    ) else {
                        throw SwanPublicRouteSurfaceError
                            .unregisteredProfile(id: selector)
                    }
                    return surface
                }
                // Read once and resolve from the bytes, so the advertisement
                // check below sees exactly the artifact the surface came from
                // rather than re-reading a file that could have changed.
                let data: Data
                do {
                    data = try Data(
                        contentsOf: URL(fileURLWithPath: selector),
                        options: [.mappedIfSafe]
                    )
                } catch {
                    throw SwanPublicRouteSurfaceError.unreadableProfile
                }
                let surface = try SwanPublicRouteSurface.resolve(profileData: data)
                try Self.requireAdvertisedEndpointsAreServed(
                    profileData: data,
                    surface: surface
                )
                return surface
            } catch let error as SwanPublicRouteSurfaceError {
                throw ValidationError("--public-profile is unusable: \(error)")
            }
        }

        /// A selector is a path when it looks like one. A profile id is a
        /// dotted-and-dashed lexicon-style token: it contains no path separator
        /// and no `.json` suffix, so neither form can be mistaken for the
        /// other.
        static func isProfilePath(_ selector: String) -> Bool {
            selector.contains("/") || selector.hasSuffix(".json")
        }

        /// Refuses a public profile artifact that advertises an endpoint this
        /// build registers no route for.
        ///
        /// A profile artifact carries an `endpoints` array; the route surface
        /// the router installs comes from a checked-in registry keyed on the
        /// artifact's `id`. Nothing reconciled the two at startup, and the
        /// registry deliberately contains an alias —
        /// `public-data-testing-2026-08-06` maps to
        /// `PublicDataTesting20260805`'s method list because the successor's
        /// wire contract is byte-identical. That alias is sound only while the
        /// two artifacts agree. Add a later successor to `Profiles/`, map it to
        /// a stale registry entry, and the process advertises a method whose
        /// route was never installed: `describeServer` and the profile name it,
        /// the namespace guard answers 404, and nothing in the build says so.
        ///
        /// It is a **subset** test, not an equality test.
        /// ``SwanPublicRouteSurface/outOfProfilePublicMethods`` is served
        /// without being declared by any profile — `resolveHandle` — and that
        /// asymmetry is intended, so only the advertise-but-do-not-serve
        /// direction is an error.
        ///
        /// This is a no-op for every profile shipped today; it is a guard
        /// against a future profile bump, which is exactly when nobody will be
        /// looking.
        static func requireAdvertisedEndpointsAreServed(
            profileData: Data,
            surface: SwanPublicRouteSurface
        ) throws {
            struct AdvertisedEndpoints: Decodable {
                let endpoints: [String]?
            }
            let advertised: [String]
            do {
                advertised = try JSONDecoder()
                    .decode(AdvertisedEndpoints.self, from: profileData)
                    .endpoints ?? []
            } catch {
                throw SwanPublicRouteSurfaceError.malformedProfile
            }
            let served = surface.servedMethodNSIDs
            let unserved = advertised.filter { !served.contains($0) }.sorted()
            guard unserved.isEmpty else {
                throw ValidationError(
                    "--public-profile '\(surface.profileID)' advertises "
                        + "\(unserved.count) endpoint(s) this build registers "
                        + "no route for: \(unserved.joined(separator: ", "))"
                )
            }
        }

        /// Conversation spaces get 60-second credentials, because a removed
        /// MLS member keeps reading until its credential expires. Every other
        /// space keeps the authority's default lifetime.
        static func spaceCredentialIssuance(
            conversationPolicyEnabled: Bool
        ) throws -> DurableSpaceCredentialAuthority.Configuration {
            try .init(spaceTypeLifetimes: conversationPolicyEnabled
                ? ["blue.catbird.labyrinth.conversation": 60] : [:])
        }

        /// Whether a resolved `--public-url` names an origin the public
        /// Internet can actually reach.
        ///
        /// Two startup interlocks below refuse a laboratory-only capability on
        /// a real deployment, and both need the same answer, so this is one
        /// predicate rather than two hand-copied ones — that duplication is how
        /// the two copies of the outbound-address table went on disagreeing
        /// about 6to4 for a month.
        ///
        /// "Non-loopback HTTPS" alone is deliberately *not* the test, and the
        /// difference is load-bearing. The disposable interop laboratory serves
        /// `https://swan.test` behind Caddy, and the serve CLI regression suite
        /// uses `https://swan.example`. Both are non-loopback HTTPS origins;
        /// both are names RFC 6761 and RFC 2606 permanently reserve, so neither
        /// can ever be delegated in public DNS. Refusing them would refuse the
        /// only topologies these laboratory options exist for. What is refused
        /// is an origin that could genuinely be resolved by a stranger.
        static func isPubliclyReachableHTTPSOrigin(_ url: URL) -> Bool {
            guard url.scheme?.lowercased() == "https" else { return false }
            guard let rawHost = url.host?.lowercased(), !rawHost.isEmpty else {
                return false
            }
            // A literal answers from the address table rather than from a name
            // suffix: `https://198.51.100.7` is documentation space and
            // `https://93.184.216.34` is not.
            if let literal = OAuthIPAddress(literal: rawHost) {
                return literal.isPublicInternetAddress
            }
            let host = rawHost.hasSuffix(".") ? String(rawHost.dropLast()) : rawHost
            // A single label has no public delegation at all.
            guard host.contains(".") else { return false }
            let reserved = Self.reservedNonPublicDNSSuffixes.contains { suffix in
                host == suffix || host.hasSuffix(".\(suffix)")
            }
            return !reserved
        }

        /// Suffixes that can never be delegated in public DNS: RFC 6761's
        /// special-use domain names, RFC 6762's `.local`, RFC 8375's
        /// `home.arpa`, RFC 2606's example domains, and the `.internal` TLD
        /// ICANN reserved for private use.
        static let reservedNonPublicDNSSuffixes: [String] = [
            "example",
            "example.com",
            "example.net",
            "example.org",
            "home.arpa",
            "internal",
            "invalid",
            "local",
            "localhost",
            "test",
        ]

        /// Refuses a laboratory PLC policy on a deployment strangers can reach.
        ///
        /// A laboratory PLC configuration accepts a plaintext-HTTP directory at
        /// an explicitly allowlisted service hostname. That is correct inside a
        /// disposable Compose network and is a mint-any-identity configuration
        /// anywhere else: whoever answers that origin, or sits on the path to
        /// it, chooses the credential and delegation keys Swan will trust.
        static func requireLaboratoryPLCStaysOffPublicOrigins(
            notificationConfigurationSelectsLaboratoryPLC: Bool,
            publicURL: URL
        ) throws {
            guard notificationConfigurationSelectsLaboratoryPLC,
                  Self.isPubliclyReachableHTTPSOrigin(publicURL)
            else { return }
            throw ValidationError(
                "--notification-config selects a laboratory PLC policy, which "
                    + "is refused when --public-url names a publicly reachable "
                    + "HTTPS origin"
            )
        }

        /// Refuses the laboratory OAuth metadata IP allowlist on a deployment
        /// strangers can reach.
        ///
        /// The allowlist approves an address for *any* hostname that resolves
        /// to it, and the complete authorization server hands remote callers a
        /// `client_id` whose metadata Swan then fetches. Composed with a public
        /// origin that is a blind SSRF into whatever the operator allowlisted.
        /// Written to the same shape as the laboratory-PLC interlock above on
        /// purpose: they are the same rule about the same boundary.
        static func requireMetadataIPAllowlistStaysOffPublicOrigins(
            allowlistedMetadataIPLiterals: [String],
            publicURL: URL
        ) throws {
            guard !allowlistedMetadataIPLiterals.isEmpty,
                  Self.isPubliclyReachableHTTPSOrigin(publicURL)
            else { return }
            throw ValidationError(
                "--oauth-allow-metadata-ip is a laboratory option, which is "
                    + "refused when --public-url names a publicly reachable "
                    + "HTTPS origin"
            )
        }

        /// Legacy sessions and their signing key move together, in BOTH
        /// directions.
        ///
        /// A flag with no key is the obvious half. The other half matters as
        /// much: a key file mounted with the flag off means an operator staged
        /// a bearer-token signing secret believing the feature was live when it
        /// was not — the kind of silent gap that is discovered by someone
        /// noticing `createSession` still 404s, long after the secret was
        /// placed on disk. Refusing to boot says so immediately.
        ///
        /// Extracted from `run()` deliberately: a refusal that can only be
        /// observed by spawning the executable is a refusal nobody re-checks.
        static func requireLegacySessionKeyMatchesFlag(
            enableLegacySessions: Bool,
            legacySessionSigningKeyFile: String?
        ) throws {
            let named = legacySessionSigningKeyFile
                .map { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
                ?? false
            if enableLegacySessions, !named {
                throw ValidationError(
                    "--enable-legacy-sessions requires an owner-only --legacy-session-signing-key-file"
                )
            }
            if !enableLegacySessions, legacySessionSigningKeyFile != nil {
                throw ValidationError(
                    "legacy session options require --enable-legacy-sessions"
                )
            }
        }

        /// The HMAC key protects the bearer session family; it is not an
        /// account signing key. Legacy `getServiceAuth` nevertheless needs a
        /// separate account-key-backed issuer, so enabling the surface must
        /// name either its dedicated owner-only account-KEK file or the
        /// already configured AppView proxy account-KEK file. The latter is
        /// reuse, not activation: a deployment may pass the dedicated options
        /// while also using `--disable-appview-proxy`.
        struct LegacySessionAccountKeySource {
            let secretFile: URL
            let activeKeyID: String
            let keyDirectory: URL?
            let reusesAppViewProxyConfiguration: Bool
        }

        /// Secret and key-store material that has passed the legacy-session
        /// startup interlock.  The values are deliberately retained rather
        /// than re-reading their pathnames after SQLite/account-directory
        /// bootstrap: a mounted secret or key root is authority, so a later
        /// path read would reopen a TOCTOU window and make a refusal depend on
        /// partially-created storage.
        struct ValidatedLegacySessionStartupMaterial {
            let signingKey: Data
            let accountKeyConfiguration: AccountKeyEncryptionConfiguration
            let accountKeyDirectory: URL
            let accountKeyStore: FileAccountKeyStore
            let reusesAppViewProxyConfiguration: Bool
        }

        static func resolveLegacySessionAccountKeySource(
            enableLegacySessions: Bool,
            legacySessionAccountKEKFile: String?,
            legacySessionAccountKEKID: String?,
            legacySessionAccountKeyDirectory: String?,
            appViewProxyAccountKEKFile: String?,
            appViewProxyAccountKEKID: String?,
            appViewProxyAccountKeyDirectory: String?
        ) throws -> LegacySessionAccountKeySource? {
            let dedicatedOptions = [
                legacySessionAccountKEKFile,
                legacySessionAccountKEKID,
                legacySessionAccountKeyDirectory,
            ]
            if !enableLegacySessions {
                guard dedicatedOptions.allSatisfy({ $0 == nil }) else {
                    throw ValidationError(
                        "legacy session account-key options require --enable-legacy-sessions"
                    )
                }
                return nil
            }

            if let appViewProxyAccountKEKFile {
                guard dedicatedOptions.allSatisfy({ $0 == nil }) else {
                    throw ValidationError(
                        "legacy session account-key options cannot be combined with --appview-proxy-account-kek-file"
                    )
                }
                guard !appViewProxyAccountKEKFile
                    .trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    throw ValidationError(
                        "--enable-legacy-sessions requires a non-empty owner-only account-KEK file"
                    )
                }
                if let appViewProxyAccountKEKID,
                   appViewProxyAccountKEKID
                    .trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    throw ValidationError(
                        "--appview-proxy-account-kek-id must not be empty"
                    )
                }
                if let appViewProxyAccountKeyDirectory,
                   appViewProxyAccountKeyDirectory
                    .trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    throw ValidationError(
                        "--appview-proxy-account-key-directory must not be empty"
                    )
                }
                return LegacySessionAccountKeySource(
                    secretFile: URL(fileURLWithPath: appViewProxyAccountKEKFile),
                    activeKeyID: appViewProxyAccountKEKID ?? "primary",
                    keyDirectory: appViewProxyAccountKeyDirectory.map {
                        URL(fileURLWithPath: $0)
                    },
                    reusesAppViewProxyConfiguration: true
                )
            }

            guard let legacySessionAccountKEKFile,
                  !legacySessionAccountKEKFile
                    .trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw ValidationError(
                    "--enable-legacy-sessions requires an owner-only --legacy-session-account-kek-file or --appview-proxy-account-kek-file"
                )
            }
            if let legacySessionAccountKEKID,
               legacySessionAccountKEKID
                .trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                throw ValidationError(
                    "--legacy-session-account-kek-id must not be empty"
                )
            }
            if let legacySessionAccountKeyDirectory,
               legacySessionAccountKeyDirectory
                .trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                throw ValidationError(
                    "--legacy-session-account-key-directory must not be empty"
                )
            }
            return LegacySessionAccountKeySource(
                secretFile: URL(fileURLWithPath: legacySessionAccountKEKFile),
                activeKeyID: legacySessionAccountKEKID ?? "primary",
                keyDirectory: legacySessionAccountKeyDirectory.map {
                    URL(fileURLWithPath: $0)
                },
                reusesAppViewProxyConfiguration: false
            )
        }

        /// Legacy-session material that passed the read-only half of the
        /// startup interlock: both mounted secrets are decoded and the key
        /// root is opened with `O_NOFOLLOW` and validated as an existing
        /// owner-only directory whose contents pass the store's read-only
        /// preflight.  Producing this creates and writes nothing,
        /// so `serve` obtains it before the service-directory lease creates
        /// the data directory.  The validated key-root descriptor stays open
        /// until `openAccountKeyStore()` hands it to `FileAccountKeyStore`,
        /// so the store is built from the exact directory that passed
        /// validation and the pathname is never reopened.
        final class PinnedLegacySessionStartupMaterial {
            let signingKey: Data
            let accountKeyConfiguration: AccountKeyEncryptionConfiguration
            let accountKeyDirectory: URL
            let reusesAppViewProxyConfiguration: Bool
            private let accountKeyDirectoryDescriptor: Int32

            fileprivate init(
                signingKey: Data,
                accountKeyConfiguration: AccountKeyEncryptionConfiguration,
                accountKeyDirectory: URL,
                accountKeyDirectoryDescriptor: Int32,
                reusesAppViewProxyConfiguration: Bool
            ) {
                self.signingKey = signingKey
                self.accountKeyConfiguration = accountKeyConfiguration
                self.accountKeyDirectory = accountKeyDirectory
                self.accountKeyDirectoryDescriptor = accountKeyDirectoryDescriptor
                self.reusesAppViewProxyConfiguration = reusesAppViewProxyConfiguration
            }

            deinit { _ = close(accountKeyDirectoryDescriptor) }

            /// The writing half of the interlock.  Opening the store creates
            /// its writer lock and active-key marker and finishes any
            /// interrupted provisioning journal inside the key root, so
            /// `serve` calls this only while it holds the service-directory
            /// lease: the default key root is `<data-directory>/keys`, which
            /// an offline snapshot copies under the exclusive lease.
            func openAccountKeyStore() throws -> ValidatedLegacySessionStartupMaterial {
                let accountKeyStore: FileAccountKeyStore
                do {
                    // The store duplicates the validated descriptor, so a
                    // concurrent rename or replacement of the pathname
                    // cannot redirect initialization.
                    accountKeyStore = try FileAccountKeyStore(
                        existingRootDirectoryDescriptor: accountKeyDirectoryDescriptor,
                        configuration: accountKeyConfiguration
                    )
                } catch {
                    throw ValidationError(
                        "legacy-session account-key-backed service-token issuer is unavailable"
                    )
                }
                return ValidatedLegacySessionStartupMaterial(
                    signingKey: signingKey,
                    accountKeyConfiguration: accountKeyConfiguration,
                    accountKeyDirectory: accountKeyDirectory,
                    accountKeyStore: accountKeyStore,
                    reusesAppViewProxyConfiguration: reusesAppViewProxyConfiguration
                )
            }
        }

        /// Both halves of the legacy-session interlock in one call, for
        /// callers that hold no service-directory lease (focused tests and
        /// offline composition).  `serve` calls the halves separately: the
        /// read-only validation before the lease, the key-store writes
        /// under it.
        static func preflightLegacySessionStartupMaterial(
            enableLegacySessions: Bool,
            legacySessionSigningKeyFile: String?,
            accountKeySource: LegacySessionAccountKeySource?,
            dataDirectory: URL
        ) throws -> ValidatedLegacySessionStartupMaterial? {
            try validateLegacySessionMountedSecrets(
                enableLegacySessions: enableLegacySessions,
                legacySessionSigningKeyFile: legacySessionSigningKeyFile,
                accountKeySource: accountKeySource,
                dataDirectory: dataDirectory
            )?.openAccountKeyStore()
        }

        /// Validate every owner-only input needed by the legacy-session
        /// surface (HMAC signing key, account KEK, existing owner-only key
        /// root and its contents) without creating or writing anything.
        /// `serve` runs this before the service-directory lease, control
        /// database, migration, account directory, or repository bootstrap
        /// can create state, so a refusal leaves no data directory behind.
        static func validateLegacySessionMountedSecrets(
            enableLegacySessions: Bool,
            legacySessionSigningKeyFile: String?,
            accountKeySource: LegacySessionAccountKeySource?,
            dataDirectory: URL
        ) throws -> PinnedLegacySessionStartupMaterial? {
            guard enableLegacySessions else { return nil }

            guard let signingKeyFile = legacySessionSigningKeyFile,
                  !signingKeyFile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            else {
                throw ValidationError(
                    "--enable-legacy-sessions requires an owner-only --legacy-session-signing-key-file"
                )
            }

            let signingKey: Data
            do {
                signingKey = try AccountProvisioningSecrets
                    .requiredMounted32ByteSecret(
                        secretFile: URL(fileURLWithPath: signingKeyFile)
                    )
            } catch {
                throw ValidationError(
                    "--enable-legacy-sessions requires a readable owner-only --legacy-session-signing-key-file"
                )
            }

            guard let accountKeySource else {
                throw ValidationError(
                    "--enable-legacy-sessions requires an owner-only --legacy-session-account-kek-file or --appview-proxy-account-kek-file"
                )
            }

            let accountKeyConfiguration: AccountKeyEncryptionConfiguration
            do {
                accountKeyConfiguration = try AccountProvisioningSecrets
                    .requiredMountedAccountKeyConfiguration(
                        activeKeyID: accountKeySource.activeKeyID,
                        secretFile: accountKeySource.secretFile
                    )
            } catch {
                throw ValidationError(
                    "legacy-session account-key-backed service-token issuer is unavailable"
                )
            }

            let accountKeyDirectory = accountKeySource.keyDirectory
                ?? dataDirectory.appending(path: "keys")
            let accountKeyDirectoryDescriptor: Int32
            do {
                // The normal pathname constructor is allowed to create a
                // missing root for provisioning commands. `serve` instead
                // opens and validates the mounted root once and pins this
                // descriptor; the store is later built from it alone.
                let descriptor =
                    try requireExistingOwnerOnlyKeyDirectory(accountKeyDirectory)
                // Refuse the root's contents (writer lock, active-KEK
                // marker, provisioning journal) here too, read-only, with
                // the same checks the store applies when it opens.
                do {
                    try FileAccountKeyStore.preflightExistingRoot(
                        directoryDescriptor: descriptor,
                        configuration: accountKeyConfiguration
                    )
                } catch {
                    _ = close(descriptor)
                    throw error
                }
                accountKeyDirectoryDescriptor = descriptor
            } catch {
                throw ValidationError(
                    "legacy-session account-key-backed service-token issuer is unavailable"
                )
            }

            return PinnedLegacySessionStartupMaterial(
                signingKey: signingKey,
                accountKeyConfiguration: accountKeyConfiguration,
                accountKeyDirectory: accountKeyDirectory,
                accountKeyDirectoryDescriptor: accountKeyDirectoryDescriptor,
                reusesAppViewProxyConfiguration:
                    accountKeySource.reusesAppViewProxyConfiguration
            )
        }

        static func makeLegacySessionServiceAuthIssuer(
            source: LegacySessionAccountKeySource,
            accounts: DurableAccountDirectory,
            defaultKeyDirectory: URL
            ) throws -> any SwanProxyServiceTokenIssuing {
            let keyConfiguration = try AccountProvisioningSecrets
                .requiredMountedAccountKeyConfiguration(
                    activeKeyID: source.activeKeyID,
                    secretFile: source.secretFile
                )
            let keyDirectory = source.keyDirectory ?? defaultKeyDirectory
            let keyStore = try withExistingOwnerOnlyKeyDirectory(keyDirectory) {
                descriptor in
                try FileAccountKeyStore(
                    existingRootDirectoryDescriptor: descriptor,
                    configuration: keyConfiguration
                )
            }
            return LocalAccountProxyServiceTokenIssuer(
                accounts: accounts,
                keyStore: keyStore
            )
        }

        /// Compose an issuer from the key store that passed the startup
        /// preflight.  This overload is the production path; the pathname-
        /// based overload above remains available to focused unit tests and
        /// offline callers that intentionally own their own setup.
        static func makeLegacySessionServiceAuthIssuer(
            accounts: DurableAccountDirectory,
            keyStore: FileAccountKeyStore
        ) -> any SwanProxyServiceTokenIssuing {
            LocalAccountProxyServiceTokenIssuer(
                accounts: accounts,
                keyStore: keyStore
            )
        }

        // MARK: - Account program startup configuration (Task 2)

        /// The container default for the compiled account portal assets. The
        /// runtime image copies `web/build` to this exact path, so an
        /// unconfigured `--enable-account-portal` deployment resolves here.
        static let defaultAccountPortalDirectory = "/usr/local/share/swan/account"

        /// Parses the `--signup-policy` option into the one `SignupPolicy`
        /// that governs both the portal advertisement and
        /// `SwanHTTPConfiguration.inviteCodeRequired`. An unrecognized value
        /// is a startup refusal, never a silent fallback to `closed`.
        static func parseSignupPolicy(_ raw: String?) throws -> SignupPolicy {
            guard let raw else { return .closed }
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let policy = SignupPolicy(rawValue: trimmed) else {
                throw ValidationError(
                    "--signup-policy must be one of closed, inviteRequired, or openProtected"
                )
            }
            return policy
        }

        /// Resolves `--account-portal-directory` to the container default when
        /// omitted, and validates an explicit override as an existing
        /// directory. The default is deliberately not probed: the container
        /// path is a deployment fact, and a local process that enables the
        /// portal without mounting assets must fail at the first asset read
        /// rather than at startup.
        static func resolveAccountPortalDirectory(_ raw: String?) throws -> URL {
            let path = raw?.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let path, !path.isEmpty else {
                return URL(fileURLWithPath: defaultAccountPortalDirectory)
            }
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(
                atPath: path,
                isDirectory: &isDirectory
            ), isDirectory.boolValue else {
                throw ValidationError(
                    "--account-portal-directory must name an existing directory"
                )
            }
            return URL(fileURLWithPath: path)
        }

        /// Validates an HTTPS public origin for the portal and the did:web
        /// claim endpoint, reusing `SwanAccountPortalConfiguration`'s origin
        /// validation so the two surfaces cannot drift apart.
        static func validateHTTPSOrigin(_ url: URL, option: String) throws {
            do {
                _ = try SwanAccountPortalConfiguration(
                    publicOrigin: url,
                    staticDirectory: URL(fileURLWithPath: "/")
                )
            } catch {
                throw ValidationError("\(option) must be an HTTPS origin")
            }
        }

        /// Parses the `--email-smtp-mode` option. `nil` selects the Mailpit
        /// laboratory default; an explicit mode is a refusal when it is not
        /// one of the three supported values.
        static func parseSMTPMode(_ raw: String?) throws -> SMTPMode? {
            guard let raw else { return nil }
            switch raw.trimmingCharacters(in: .whitespacesAndNewlines) {
            case "startTLS": return .startTLS
            case "implicitTLS": return .implicitTLS
            case "plaintextLab": return .plaintextLab
            default:
                throw ValidationError(
                    "--email-smtp-mode must be one of startTLS, implicitTLS, or plaintextLab"
                )
            }
        }

        /// Parses the `--email-smtp-mechanism` option.
        static func parseSMTPMechanism(_ raw: String?) throws -> SMTPAuthMechanism? {
            guard let raw else { return nil }
            switch raw.trimmingCharacters(in: .whitespacesAndNewlines) {
            case "plain": return .plain
            case "login": return .login
            case "xoauth2": return .xoauth2
            default:
                throw ValidationError(
                    "--email-smtp-mechanism must be one of plain, login, or xoauth2"
                )
            }
        }

        /// Reads an SMTP credential from an owner-only mounted file. The
        /// value is never echoed into descriptions, logs, errors, or test
        /// snapshots; only the file path is validated here.
        static func readMountedSMTPCredential(
            file: String?,
            option: String
        ) throws -> String? {
            guard let file else { return nil }
            let trimmed = file.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                throw ValidationError("\(option) must not be empty")
            }
            let data = try readBoundedRegularFileNoFollow(
                URL(fileURLWithPath: trimmed),
                maximumBytes: 4 * 1_024,
                validationMessage: "\(option) is unavailable"
            )
            var normalized = data
            if normalized.last == 0x0A {
                normalized.removeLast()
                if normalized.last == 0x0D {
                    normalized.removeLast()
                }
            }
            guard !normalized.isEmpty,
                  !normalized.contains(0),
                  let value = String(data: normalized, encoding: .utf8) else {
                throw ValidationError("\(option) is invalid")
            }
            return value
        }

        /// Public signup always needs an authenticated STARTTLS or implicit-TLS
        /// email-proof/outbox path. The NIO production transport deliberately
        /// rejects `plaintextLab`; accepting it here would defer a known
        /// startup failure until the first delivery attempt.
        static func requireAuthenticatedSMTPForPublicSignup(
            policy: SignupPolicy,
            emailSMTPMode: String?
        ) throws {
            guard policy == .closed else {
                guard let emailSMTPMode else {
                    throw ValidationError(
                        "--signup-policy \(policy.rawValue) requires --email-smtp-mode"
                    )
                }
                let mode = try parseSMTPMode(emailSMTPMode)
                guard mode == .startTLS || mode == .implicitTLS else {
                    throw ValidationError(
                        "--signup-policy \(policy.rawValue) requires authenticated startTLS or implicitTLS SMTP"
                    )
                }
                return
            }
            if let emailSMTPMode {
                guard try parseSMTPMode(emailSMTPMode) == .plaintextLab else {
                    throw ValidationError(
                        "--email-smtp-mode plaintextLab is only available when public signup is disabled"
                    )
                }
            }
        }

        /// Resolves the authenticated SMTP configuration from the parsed
        /// options. `nil` mode selects the Mailpit laboratory default (the
        /// existing `--enable-email-recovery` path); an explicit non-lab mode
        /// without the full username/password/mechanism/expected-hostname set
        /// is a refusal, never a silent fallback to Mailpit.
        static func resolveAuthenticatedSMTPConfiguration(
            mode: SMTPMode?,
            host: String?,
            port: Int?,
            usernameFile: String?,
            passwordFile: String?,
            mechanism: SMTPAuthMechanism?,
            expectedHostname: String?,
            maximumAttempts: Int?
        ) throws -> AuthenticatedSMTPConfiguration? {
            guard let mode else { return nil }
            let username = try readMountedSMTPCredential(
                file: usernameFile,
                option: "--email-smtp-username-file"
            )
            let password = try readMountedSMTPCredential(
                file: passwordFile,
                option: "--email-smtp-password-file"
            )
            // The Mailpit laboratory defaults are only for plaintextLab; a
            // non-lab mode with omitted host/port would silently target
            // mailpit:1025, so refuse instead.
            if mode != .plaintextLab {
                guard let host,
                      !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                      port != nil else {
                    throw ValidationError(
                        "--email-smtp-mode \(Self.smtpModeName(mode)) requires --email-smtp-host and --email-smtp-port"
                    )
                }
            }
            do {
                return try AuthenticatedSMTPConfiguration(
                    host: host?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "mailpit",
                    port: port ?? 1025,
                    mode: mode,
                    username: username,
                    password: password,
                    mechanism: mechanism,
                    expectedHostname: expectedHostname?.trimmingCharacters(in: .whitespacesAndNewlines),
                    maximumAttempts: maximumAttempts ?? 3
                )
            } catch {
                throw ValidationError(
                    "--email-smtp-mode \(Self.smtpModeName(mode)) requires an owner-only --email-smtp-username-file, --email-smtp-password-file, --email-smtp-mechanism, and --email-smtp-expected-hostname"
                )
            }
        }

        /// Renders an SMTP mode for operator-facing messages without exposing
        /// any credential material.
        static func smtpModeName(_ mode: SMTPMode) -> String {
            switch mode {
            case .startTLS: "startTLS"
            case .implicitTLS: "implicitTLS"
            case .plaintextLab: "plaintextLab"
            }
        }

        struct ValidatedAccountProgramStartupMaterial: Sendable {
            let signupSecret: SignupSecret?
            let signupAccountKeyConfiguration: AccountKeyEncryptionConfiguration
            let accountKEK: Data
            let didWebSigningKey: Data
        }

        /// Validate every mounted secret consumed by the opt-in account
        /// runtime before SQLite, repository bootstrap, or a listener exists.
        /// A process environment is not an owner-only mounted authority and
        /// therefore cannot configure signup or did:web in this production
        /// path. Decoded values are retained so composition does not reopen a
        /// pathname or consult a different source after storage exists.
        static func preflightAccountProgramStartupMaterial(
            enableAccountPortal: Bool,
            signupPolicy: SignupPolicy,
            signupSecretFile: String?,
            signupAccountKEKFile: String?,
            signupAccountKEKID: String?,
            didWebSigningKeyFile: String?
        ) throws -> ValidatedAccountProgramStartupMaterial? {
            guard enableAccountPortal else { return nil }
            guard let didWebSigningKeyFile,
                  !didWebSigningKeyFile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw ValidationError(
                    "--enable-account-portal requires an owner-only --did-web-signing-key-file"
                )
            }
            let didWebSigningKey: Data
            do {
                didWebSigningKey = try AccountProvisioningSecrets.requiredMounted32ByteSecret(
                    secretFile: URL(fileURLWithPath: didWebSigningKeyFile)
                )
            } catch {
                throw ValidationError("--did-web-signing-key-file is unavailable")
            }

            guard let signupAccountKEKFile,
                  !signupAccountKEKFile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw ValidationError(
                    "--enable-account-portal requires an owner-only --signup-account-kek-file"
                )
            }
            let accountKEK: Data
            do {
                accountKEK = try AccountProvisioningSecrets.requiredMounted32ByteSecret(
                    secretFile: URL(fileURLWithPath: signupAccountKEKFile)
                )
            } catch {
                throw ValidationError("--signup-account-kek-file is unavailable")
            }
            let signupSecret: SignupSecret?
            if signupPolicy == .closed {
                guard signupSecretFile == nil else {
                    throw ValidationError(
                        "--signup-secret-file requires --signup-policy inviteRequired or openProtected"
                    )
                }
                signupSecret = nil
            } else {
                guard let signupSecretFile,
                      !signupSecretFile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    throw ValidationError(
                        "--signup-policy \(signupPolicy.rawValue) requires an owner-only --signup-secret-file"
                    )
                }
                do {
                    signupSecret = try SignupSecret(
                        AccountProvisioningSecrets.requiredMounted32ByteSecret(
                            secretFile: URL(fileURLWithPath: signupSecretFile)
                        )
                    )
                } catch {
                    throw ValidationError("--signup-secret-file is unavailable")
                }
            }
            let signupAccountKeyConfiguration: AccountKeyEncryptionConfiguration
            do {
                signupAccountKeyConfiguration = try AccountProvisioningSecrets
                    .requiredMountedAccountKeyConfiguration(
                        activeKeyID: signupAccountKEKID ?? "primary",
                        secretFile: URL(fileURLWithPath: signupAccountKEKFile)
                    )
            } catch {
                throw ValidationError("--signup-account-kek-file is unavailable")
            }
            return ValidatedAccountProgramStartupMaterial(
                signupSecret: signupSecret,
                signupAccountKeyConfiguration: signupAccountKeyConfiguration,
                accountKEK: accountKEK,
                didWebSigningKey: didWebSigningKey
            )
        }

        func run() async throws {
            guard (1 ... 1_000_000).contains(spaceOplogRetention) else {
                throw ValidationError(
                    "--space-oplog-retention must be from 1 through 1000000"
                )
            }
            // Bounded before anything reads it. `SwanHTTPConfiguration` only
            // `precondition`s `> 0`, and a precondition failure is a crash
            // rather than a startup refusal an operator can read.
            guard (1 ... 65_536).contains(maxConnections) else {
                throw ValidationError(
                    "--max-connections must be from 1 through 65536"
                )
            }
            let loginClientIdentityPolicy: SwanLoginClientIdentityPolicy
            do {
                loginClientIdentityPolicy = try SwanLoginClientIdentityPolicy(
                    trustedProxyPeerLiterals: loginTrustedProxyPeers
                )
            } catch {
                throw ValidationError(
                    "--login-trusted-proxy-peer must be a literal IPv4 or IPv6 address"
                )
            }
            if !enableLocalSpaceInterop {
                guard spaceAccountKEKFile == nil,
                      spaceAccountKEKID == nil,
                      spaceAccountKeyDirectory == nil else {
                    throw ValidationError(
                        "space account key options require --enable-local-space-interop"
                    )
                }
            } else {
                guard let spaceAccountKEKFile,
                      !spaceAccountKEKFile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                      spaceAccountKEKID.map({
                          !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                      }) ?? true,
                      spaceAccountKeyDirectory.map({
                          !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                      }) ?? true else {
                    throw ValidationError(
                        "--enable-local-space-interop requires an owner-only --space-account-kek-file"
                    )
                }
            }
            if !enablePublicRepositoryMutations {
                guard publicAccountKEKFile == nil,
                      publicAccountKEKID == nil,
                      publicAccountKeyDirectory == nil else {
                    throw ValidationError(
                        "public account key options require --enable-public-repository-mutations"
                    )
                }
            } else {
                guard let publicAccountKEKFile,
                      !publicAccountKEKFile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                      publicAccountKEKID.map({
                          !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                      }) ?? true,
                      publicAccountKeyDirectory.map({
                          !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                      }) ?? true else {
                    throw ValidationError(
                        "--enable-public-repository-mutations requires an owner-only --public-account-kek-file"
                    )
                }
            }
            if !enableNotificationDelivery {
                guard notificationAccountKEKFile == nil,
                      notificationAccountKEKID == nil,
                      notificationAccountKeyDirectory == nil else {
                    throw ValidationError(
                        "notification account options require --enable-notification-delivery"
                    )
                }
            } else {
                guard notificationAccountKEKFile.map({
                          !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                      }) ?? true,
                      notificationAccountKEKID.map({
                          !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                      }) ?? true,
                      notificationAccountKeyDirectory.map({
                          !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                      }) ?? true else {
                    throw ValidationError("notification account key-store options are invalid")
                }
            }
            try Self.requireLegacySessionKeyMatchesFlag(
                enableLegacySessions: enableLegacySessions,
                legacySessionSigningKeyFile: legacySessionSigningKeyFile
            )
            let legacySessionAccountKeySource = try Self
                .resolveLegacySessionAccountKeySource(
                    enableLegacySessions: enableLegacySessions,
                    legacySessionAccountKEKFile: legacySessionAccountKEKFile,
                    legacySessionAccountKEKID: legacySessionAccountKEKID,
                    legacySessionAccountKeyDirectory: legacySessionAccountKeyDirectory,
                    appViewProxyAccountKEKFile: appViewProxyAccountKEKFile,
                    appViewProxyAccountKEKID: appViewProxyAccountKEKID,
                    appViewProxyAccountKeyDirectory: appViewProxyAccountKeyDirectory
                )
            if !enableEmailRecovery {
                guard emailProofKeyFile == nil,
                      emailSender == nil,
                      emailWorkerID == nil,
                      // `--email-smtp-host`/`--email-smtp-port` are shared
                      // with the account program's authenticated SMTP
                      // configuration, so they are exempt when that surface
                      // is enabled with an explicit mode; without a mode they
                      // remain Mailpit-path options.
                      (emailSMTPHost == nil && emailSMTPPort == nil)
                        || (enableAccountPortal && emailSMTPMode != nil) else {
                    throw ValidationError(
                        "email recovery options require --enable-email-recovery"
                    )
                }
            } else {
                guard let emailProofKeyFile,
                      !emailProofKeyFile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                      let emailSender,
                      !emailSender.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                      emailSMTPHost.map({
                          !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                      }) ?? true,
                      emailWorkerID.map({
                          !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                      }) ?? true,
                      emailSMTPPort.map({ (1 ... 65_535).contains($0) }) ?? true else {
                    throw ValidationError(
                        "--enable-email-recovery requires an owner-only --email-proof-key-file and canonical --email-sender"
                    )
                }
            }
            // Account program startup configuration (Task 2). All refusals
            // run before any storage, key store, or listener exists.
            // The resolved portal directory is validated here; Task 5 consumes
            // it when it constructs the portal service.
            let accountPortalDirectoryURL = try Self.resolveAccountPortalDirectory(
                accountPortalDirectory
            )
            // The parsed policy is a non-optional enum; the raw option stays
            // `String?` so the opt-in guard below can distinguish "option
            // omitted" from "policy closed". Shadowing the option with the
            // parsed value made `signupPolicy == nil` always false and refused
            // every `serve` invocation without `--enable-account-portal`.
            let resolvedSignupPolicy = try Self.parseSignupPolicy(signupPolicy)
            if !enableAccountPortal {
                guard accountPortalDirectory == nil,
                      signupPolicy == nil,
                      turnstileSecretFile == nil,
                      signupSecretFile == nil,
                      signupAccountKEKFile == nil,
                      signupAccountKEKID == nil,
                      signupAccountKeyDirectory == nil,
                      emailSMTPMode == nil,
                      emailSMTPUsernameFile == nil,
                      emailSMTPPasswordFile == nil,
                      emailSMTPMechanism == nil,
                      emailSMTPExpectedHostname == nil,
                      emailSMTPMaxAttempts == nil,
                      didWebRevalidationIntervalSeconds == 3600,
                      didWebRevalidationGraceSeconds == 86_400,
                      didWebSigningKeyFile == nil else {
                    throw ValidationError(
                        "account program options require --enable-account-portal"
                    )
                }
            } else {
                guard (1 ... 86_400).contains(didWebRevalidationIntervalSeconds) else {
                    throw ValidationError(
                        "--did-web-revalidation-interval-seconds must be from 1 through 86400"
                    )
                }
                guard (1 ... 86_400).contains(didWebRevalidationGraceSeconds) else {
                    throw ValidationError(
                        "--did-web-revalidation-grace-seconds must be from 1 through 86400"
                    )
                }
                // SMTP credential options without an explicit mode would be
                // silently discarded onto the Mailpit laboratory path; refuse
                // instead (mirrors the turnstile-requires-openProtected check).
                guard emailSMTPMode != nil
                    || (emailSMTPUsernameFile == nil
                        && emailSMTPPasswordFile == nil
                        && emailSMTPMechanism == nil
                        && emailSMTPExpectedHostname == nil
                        && emailSMTPMaxAttempts == nil) else {
                    throw ValidationError(
                        "--email-smtp-username-file, --email-smtp-password-file, --email-smtp-mechanism, --email-smtp-expected-hostname, and --email-smtp-max-attempts require --email-smtp-mode"
                    )
                }
                if resolvedSignupPolicy == .openProtected {
                    guard let turnstileSecretFile,
                          !turnstileSecretFile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                        throw ValidationError(
                            "--signup-policy openProtected requires an owner-only --turnstile-secret-file"
                        )
                    }
                } else {
                    guard turnstileSecretFile == nil else {
                        throw ValidationError(
                            "--turnstile-secret-file requires --signup-policy openProtected"
                        )
                    }
                }
                try Self.requireAuthenticatedSMTPForPublicSignup(
                    policy: resolvedSignupPolicy,
                    emailSMTPMode: emailSMTPMode
                )
            }
            let smtpMode = try Self.parseSMTPMode(emailSMTPMode)
            let smtpMechanism = try Self.parseSMTPMechanism(emailSMTPMechanism)
            // Resolved and validated here so an incomplete authenticated SMTP
            // configuration is a startup refusal; Task 3 consumes the value
            // when it assembles the signup email worker.
            _ = try Self.resolveAuthenticatedSMTPConfiguration(
                mode: smtpMode,
                host: emailSMTPHost,
                port: emailSMTPPort,
                usernameFile: emailSMTPUsernameFile,
                passwordFile: emailSMTPPasswordFile,
                mechanism: smtpMechanism,
                expectedHostname: emailSMTPExpectedHostname,
                maximumAttempts: emailSMTPMaxAttempts
            )
            // A public signup policy (inviteRequired or openProtected)
            // assembles the signup runtime: the email-proof/invite HMAC
            // secret and the account key store are both required, and
            // neither may be silently replaced by a weaker default. This
            // runs after the SMTP refusals so an incomplete SMTP
            // configuration reports the SMTP problem first.
            if enableAccountPortal && resolvedSignupPolicy == .closed {
                // The closed policy does not assemble public signup, but the
                // opted-in account portal still needs its mounted account KEK
                // for MFA envelope protection. Only the signup HMAC secret is
                // forbidden on this path.
                guard signupSecretFile == nil else {
                    throw ValidationError(
                        "--signup-secret-file requires --signup-policy inviteRequired or openProtected"
                    )
                }
            }
            guard !enableManagementPLCProvisioning || managementPort != nil else {
                throw ValidationError("--enable-management-plc-provisioning requires --management-port")
            }
            guard !enableManagementPermanentDeletion || managementPort != nil else {
                throw ValidationError("--enable-management-permanent-deletion requires --management-port")
            }
            guard !enableManagementFirehoseSync || managementPort != nil else {
                throw ValidationError("--enable-management-firehose-sync requires --management-port")
            }
            guard !enableManagementFirehoseSync || enablePublicFirehose else {
                throw ValidationError("--enable-management-firehose-sync requires --enable-public-firehose")
            }
            let managementNeedsAccountKeyStore =
                enableManagementPLCProvisioning
                    || enableManagementPermanentDeletion
            if !managementNeedsAccountKeyStore {
                guard managementAccountKEKFile == nil,
                      managementAccountKeyDirectory == nil,
                      managementAccountKEKID == nil
                else {
                    throw ValidationError(
                        "management account key options require --enable-management-plc-provisioning or --enable-management-permanent-deletion"
                    )
                }
            } else {
                guard managementAccountKEKID.map({
                          !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                      }) ?? true,
                      managementAccountKeyDirectory.map({
                          !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                      }) ?? true
                else {
                    throw ValidationError("management account key-store options are invalid")
                }
            }
            if !enableManagementPermanentDeletion {
                guard managementDeletionPLCOrigin == nil,
                      !managementDeletionPLCLaboratory,
                      managementDeletionPLCLaboratoryAllowlistedHost == nil,
                      managementDeletionPLCReferenceCompatibility == nil else {
                    throw ValidationError(
                        "management deletion PLC options require --enable-management-permanent-deletion"
                    )
                }
            }
            let managementDeletionPLCConfiguration:
                PLCClientConfiguration?
            if enableManagementPermanentDeletion {
                managementDeletionPLCConfiguration =
                    try makePermanentDeletionPLCConfiguration(
                        origin: managementDeletionPLCOrigin,
                        laboratory: managementDeletionPLCLaboratory,
                        laboratoryAllowlistedHost:
                            managementDeletionPLCLaboratoryAllowlistedHost,
                        referenceCompatibility:
                            managementDeletionPLCReferenceCompatibility
                    )
            } else {
                managementDeletionPLCConfiguration = nil
            }
            let loadedProfile = try ProtocolProfile.load(from: URL(fileURLWithPath: profile))
            // Resolved before any listener, database, or key store is touched.
            // An unregistered public profile is a refusal to boot, not a
            // narrower surface an operator has to notice from traffic.
            let publicRouteSurface = try Self.resolvePublicRouteSurface(
                selector: publicProfile
            )
            let baseURL = try publicURL.map { value in
                guard let url = URL(string: value) else { throw ValidationError("--public-url must be a URL") }
                return url
            } ?? {
                guard let url = URL(string: "http://\(host):\(port)") else {
                    throw ValidationError(
                        "--host and --port do not form a valid default public URL"
                    )
                }
                return url
            }()
            if enableLocalSpaceInterop,
               baseURL.scheme?.lowercased() != "https" {
                throw ValidationError(
                    "--enable-local-space-interop requires an HTTPS --public-url"
                )
            }
            // The account portal and the did:web claim endpoint are served
            // from the same public origin; both require an HTTPS origin
            // (reusing `SwanAccountPortalConfiguration`'s validation).
            if enableAccountPortal {
                try Self.validateHTTPSOrigin(
                    baseURL,
                    option: "--public-url"
                )
            }
            // The account-program mounted-secret preflight runs before any
            // control database, account directory, repository bootstrap, or
            // listener exists. Its decoded values are carried into the later
            // composition instead of reopening paths or consulting env.
            let accountProgramStartupMaterial = try Self
                .preflightAccountProgramStartupMaterial(
                    enableAccountPortal: enableAccountPortal,
                    signupPolicy: resolvedSignupPolicy,
                    signupSecretFile: signupSecretFile,
                    signupAccountKEKFile: signupAccountKEKFile,
                    signupAccountKEKID: signupAccountKEKID,
                    didWebSigningKeyFile: didWebSigningKeyFile
                )
            // Both laboratory interlocks run here: after the public origin is
            // known and before the control database, key stores, or any
            // listener exist, so a refused configuration leaves no state
            // behind.
            let notificationStartupMaterial = try ServeNotificationRuntime.preflight(
                fromFile: notificationConfig
            )
            try Self.requireLaboratoryPLCStaysOffPublicOrigins(
                notificationConfigurationSelectsLaboratoryPLC:
                notificationStartupMaterial?.selectsLaboratoryPLC ?? false,
                publicURL: baseURL
            )
            try Self.requireMetadataIPAllowlistStaysOffPublicOrigins(
                allowlistedMetadataIPLiterals: oauthMetadataAllowedIPs,
                publicURL: baseURL
            )
            let dataURL = URL(fileURLWithPath: dataDirectory)
            // Legacy bearer credentials are the one serve surface whose
            // mounted secrets must be validated as a single authority before
            // any state exists.  The read-only half runs before the service
            // lease, because the lease creates the data directory and a
            // refused configuration must leave none behind.  The pinned key
            // root becomes a store only under the lease, because the store
            // writes into it and the default root lies inside the data
            // directory that offline snapshots copy.  Keep the validated
            // bytes/configuration/store and pass them into composition below;
            // do not re-read these pathnames after bootstrap.
            var pinnedLegacySessionStartup = try Self
                .validateLegacySessionMountedSecrets(
                    enableLegacySessions: enableLegacySessions,
                    legacySessionSigningKeyFile: legacySessionSigningKeyFile,
                    accountKeySource: legacySessionAccountKeySource,
                    dataDirectory: dataURL
                )
            // The OAuth server key is a pure owner-only file read, so a
            // missing or malformed key is refused before the lease as well.
            let serverKey = try loadOAuthServerKey(fromFile: oauthServerKeyFile)
            let serviceDirectoryLease = try SwanServiceDirectoryLease(dataDirectory: dataURL)
            defer { withExtendedLifetime(serviceDirectoryLease) {} }
            // Bad key-root contents were already refused read-only above.
            // Opening the store still writes (writer lock, active-KEK
            // marker, journal recovery), so it stays under the lease. What
            // can still fail here is one of those writes (I/O, or a writer
            // lock that is owner-read-only), or a root that changed after
            // the preflight. Such a failure can leave the data directory and
            // its lease file behind; it cannot move above the lease without
            // writing outside it.
            let validatedLegacySessionStartup = try pinnedLegacySessionStartup?
                .openAccountKeyStore()
            // The store holds its own duplicate; close the validated
            // key-root descriptor now rather than when `run()` returns.
            pinnedLegacySessionStartup = nil
            let controlDatabase = try await SQLiteControlDatabase(dataDirectory: dataURL)
            var preopenedAccountDirectory: SQLitePreMigratedAccountDirectory?
            var preopenedManagementProvisioning: SwanManagementPLCProvisioningRuntime?
            var preopenedFirehoseDatabase: SQLiteFirehoseDatabase?
            do {
                if !enableManagementPermanentDeletion {
                    let pending = try await controlDatabase
                        .pendingDeletionJobs(afterDID: nil, limit: 1)
                    guard pending.isEmpty else {
                        throw ValidationError(
                            "pending permanent deletion requires --enable-management-permanent-deletion"
                        )
                    }
                }
                // Permissioned lookup never creates or migrates an account
                // database during a request. Build the complete active set
                // before the public listener exists; failures keep the
                // endpoint unavailable rather than repairing state online.
                let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
                    dataDirectory: dataURL,
                    controlStore: controlDatabase,
                    oplogRetention: spaceOplogRetention,
                    publicIdentityVerifier: SwanPublicPLCGenesisVerifier()
                )
                preopenedAccountDirectory = directory
                // The lifecycle emitter is constructed unconditionally: the
                // "unconditional enqueue, gated drain" constraint means every
                // confirmed activation durably enqueues its lifecycle batch
                // and barriered head sync even when firehose sequencing and
                // streaming are not enabled.
                let lifecycleEmitter = SQLitePublicLifecycleEmitter(
                    control: controlDatabase,
                    accounts: directory
                )
                let localSpaceRuntime: ServeLocalSpaceRuntime?
                if enableLocalSpaceInterop {
                    do {
                        localSpaceRuntime = try await .make(
                            keyDirectory: spaceAccountKeyDirectory.map {
                                URL(fileURLWithPath: $0)
                            } ?? dataURL.appending(path: "keys"),
                            kekFile: URL(fileURLWithPath: spaceAccountKEKFile!),
                            kekID: spaceAccountKEKID ?? "primary",
                            controlStore: controlDatabase
                        )
                    } catch {
                        throw ValidationError("local space interop runtime is unavailable")
                    }
                } else {
                    localSpaceRuntime = nil
                }
                let publicMutationRuntime: ServePublicMutationRuntime?
                if enablePublicRepositoryMutations {
                    do {
                        publicMutationRuntime = try await .make(
                            keyDirectory: publicAccountKeyDirectory.map {
                                URL(fileURLWithPath: $0)
                            } ?? dataURL.appending(path: "keys"),
                            kekFile: URL(fileURLWithPath: publicAccountKEKFile!),
                            kekID: publicAccountKEKID ?? "primary",
                            controlStore: controlDatabase
                        )
                    } catch {
                        throw ValidationError("public repository mutation runtime is unavailable")
                    }
                } else {
                    publicMutationRuntime = nil
                }
                // §5.7.5's composition root. The protocol lives in SwanCore so
                // SwanOAuth and SwanHTTP can name it; the 15-step
                // implementation lives in SwanInterop next to the CAR machinery
                // it needs. `swan` is the only target that depends on both, so
                // it is the only place the two can be joined — no source
                // target's `Package.swift` dependencies change.
                let lexiconResolver: (any SwanLexiconResolving)?
                if enableLexiconResolution {
                    guard enableOAuthAuthorizationServer else {
                        throw ValidationError(
                            "--enable-lexicon-resolution requires --enable-oauth-authorization-server"
                        )
                    }
                    do {
                        // The 256 KiB cap is an anti-DoS control on MST-walk and
                        // signature CPU, not a document-size preference, and the
                        // fetcher's body cap is the only thing that enforces it.
                        // `SwanLexiconResolver.init` refuses a wider policy.
                        let lexiconFetchPolicy = try OAuthRemoteFetchPolicy(
                            maximumBodyBytes: SwanLexiconResolutionBudget.maximumCARBytes
                        )
                        let lexiconFetcher = OAuthRemoteDocumentFetcher(
                            policy: lexiconFetchPolicy,
                            transport: try NIOPeerPinnedOAuthDocumentTransport(
                                maximumTransportTimeout: lexiconFetchPolicy.timeout
                            )
                        )
                        lexiconResolver = try SwanLexiconResolver(
                            // A new call site on the existing bounded DNS
                            // resolver — `_lexicon.<authority>` over the same C
                            // wire-parser that already reads `_atproto.<handle>`
                            // — not new DNS plumbing.
                            dns: SystemATHandleDNSResolver(),
                            authorities: try SwanLexiconAuthorityResolver(
                                plc: try PLCDirectoryClient(
                                    configuration: managementDeletionPLCConfiguration
                                        ?? .production()
                                ),
                                documents: try SwanPeerPinnedDIDDocumentFetcher(
                                    documents: lexiconFetcher,
                                    plcOrigin: managementDeletionPLCConfiguration?.origin
                                        ?? PLCClientConfiguration.defaultProductionOrigin
                                )
                            ),
                            fetcher: lexiconFetcher,
                            store: controlDatabase
                        )
                    } catch let error as ValidationError {
                        throw error
                    } catch {
                        throw ValidationError("lexicon resolution runtime is unavailable")
                    }
                } else {
                    lexiconResolver = nil
                }
                // Task 4 identity admission. One durable evaluator over the
                // control store backs OAuth issuance, legacy issuance, and
                // public repository mutations; it is constructible before the
                // did:web service composition because it depends only on the
                // store and the grace-policy value.
                let identityAdmission = SwanDurableIdentityAdmission(
                    bindings: controlDatabase,
                    gracePeriod: TimeInterval(didWebRevalidationGraceSeconds)
                )
                let oauthRuntime = try SwanOAuthRuntime(
                    controlStore: controlDatabase,
                    serverKey: serverKey,
                    lexiconResolver: lexiconResolver,
                    identityAdmission: identityAdmission
                )
                // Make an unsafe public identity a startup error rather than
                // silently leaving the authenticated endpoint closed. The
                // server constructs its own instance from these same values
                // when it installs the route.
                _ = try SwanOAuthResourceAuthorizer(
                    publicURL: baseURL,
                    runtime: oauthRuntime,
                    accountControlStore: controlDatabase
                )
                var logger = Logger(label: "swan")
                logger.logLevel = .info
                let enabledOAuthModes = [enableLocalhostPAR, enableLocalhostOAuth, enableOAuthAuthorizationServer]
                    .filter { $0 }.count
                guard enabledOAuthModes <= 1 else {
                    throw ValidationError("--enable-localhost-par, --enable-localhost-oauth, and --enable-oauth-authorization-server are mutually exclusive")
                }
                let localhostPARConfiguration: SwanLocalhostPARConfiguration?
                if enableLocalhostPAR {
                    do {
                        localhostPARConfiguration = try SwanLocalhostPARConfiguration(issuer: baseURL)
                    } catch {
                        throw ValidationError("--enable-localhost-par requires an HTTPS public issuer URL")
                    }
                } else {
                    localhostPARConfiguration = nil
                }
                var localhostOAuthConfiguration: SwanLocalhostOAuthConfiguration?
                if enableLocalhostOAuth {
                    do {
                        let passwordHasher = try LibsodiumArgon2idHasher()
                        let factorTokens = FactorTokenService(store: controlDatabase)
                        let accounts = DurableAccountDirectory(
                            store: controlDatabase,
                            passwordHasher: passwordHasher,
                            verificationExecutor: try Argon2idVerificationExecutor(hasher: passwordHasher),
                            loginAdmissionService: AccountLoginAdmissionService(
                                store: controlDatabase,
                                key: try AccountLoginAdmissionKey(serverKey)
                            ),
                            loginFactorTokenVerifier: factorTokens,
                            authenticationFactors: controlDatabase
                        )
                        localhostOAuthConfiguration = try SwanLocalhostOAuthConfiguration(
                            issuer: baseURL,
                            accounts: accounts
                        )
                    } catch {
                        throw ValidationError("--enable-localhost-oauth requires an HTTPS public issuer URL and usable password verification")
                    }
                } else {
                    localhostOAuthConfiguration = nil
                }
                let needsRemoteClientMetadata =
                    enableOAuthAuthorizationServer || enableLocalSpaceInterop
                let clientMetadataLoader: OAuthClientMetadataLoader?
                if needsRemoteClientMetadata {
                    do {
                        var allowlistedIPs = Set<OAuthIPAddress>()
                        for text in oauthMetadataAllowedIPs {
                            guard let address = OAuthIPAddress(literal: text) else {
                                throw ValidationError(
                                    "--oauth-allow-metadata-ip must be a literal IPv4 or IPv6 address"
                                )
                            }
                            allowlistedIPs.insert(address)
                        }
                        let fetchPolicy = try OAuthRemoteFetchPolicy(
                            allowLocalhostDevelopment:
                                enableOAuthAuthorizationServer
                                    && oauthAllowLocalhostDevelopmentClient,
                            networkAllowlist: .init(addresses: allowlistedIPs)
                        )
                        let fetcher = OAuthRemoteDocumentFetcher(
                            policy: fetchPolicy,
                            transport: try NIOPeerPinnedOAuthDocumentTransport(
                                maximumTransportTimeout: fetchPolicy.timeout
                            )
                        )
                        clientMetadataLoader = try OAuthClientMetadataLoader(
                            fetcher: fetcher,
                            controlStore: controlDatabase
                        )
                    } catch let error as ValidationError {
                        throw error
                    } catch {
                        throw ValidationError(
                            "hardened OAuth metadata fetch runtime is unavailable"
                        )
                    }
                } else {
                    guard oauthMetadataAllowedIPs.isEmpty else {
                        throw ValidationError(
                            "--oauth-allow-metadata-ip requires --enable-oauth-authorization-server or --enable-local-space-interop"
                        )
                    }
                    clientMetadataLoader = nil
                }
                guard enableOAuthAuthorizationServer
                        || !oauthAllowLocalhostDevelopmentClient else {
                    throw ValidationError(
                        "--oauth-allow-localhost-development-client requires --enable-oauth-authorization-server"
                    )
                }
                var authorizationServerConfiguration: SwanOAuthAuthorizationServerConfiguration?
                if enableOAuthAuthorizationServer {
                    do {
                        guard let clientMetadataLoader else {
                            throw SwanError.unavailable(
                                "OAuth client metadata loader is unavailable"
                            )
                        }
                        let passwordHasher = try LibsodiumArgon2idHasher()
                        let factorTokens = FactorTokenService(store: controlDatabase)
                        let accounts = DurableAccountDirectory(
                            store: controlDatabase,
                            passwordHasher: passwordHasher,
                            verificationExecutor: try Argon2idVerificationExecutor(hasher: passwordHasher),
                            loginAdmissionService: AccountLoginAdmissionService(
                                store: controlDatabase,
                                key: try AccountLoginAdmissionKey(serverKey)
                            ),
                            loginFactorTokenVerifier: factorTokens,
                            authenticationFactors: controlDatabase
                        )
                        authorizationServerConfiguration = try SwanOAuthAuthorizationServerConfiguration(
                            issuer: baseURL,
                            protectedResource: baseURL,
                            accounts: accounts,
                            clientMetadataLoader: clientMetadataLoader,
                            // The transition entries are the upstream-standard hints
                            // (build-metadata.ts calls them "not a specced behavior"), and
                            // Swan's grammar already parses and admits all three at PAR
                            // (`AtprotoScope.parse`; granted set pinned by
                            // `SwanOAuthTests`). What was missing was the advertisement:
                            // the atproto-oauth Rust crate (resources.rs,
                            // ScopesSupportedMustIncludeTransitionGeneric) refuses to
                            // begin sign-in against any server whose scopes_supported
                            // omits transition:generic — observed as bulleted.app
                            // declining swan.place — and Catbird's nest client requests
                            // transition scopes at login. §6.6's rule that permission
                            // families are not enumerated is unchanged.
                            scopesSupported: [
                                "atproto",
                                "transition:generic",
                                "transition:email",
                                "transition:chat.bsky",
                            ]
                        )
                    } catch let error as ValidationError {
                        throw error
                    } catch {
                        throw ValidationError("--enable-oauth-authorization-server requires an HTTPS issuer, durable password verification, and a hardened metadata fetch runtime")
                    }
                } else {
                    authorizationServerConfiguration = nil
                }
                let clientAttestationPolicy:
                    any SpaceCredentialClientAttestationPolicy
                if enableLocalSpaceInterop, let clientMetadataLoader {
                    do {
                        clientAttestationPolicy =
                            try DurableSpaceCredentialClientAttestationPolicy(
                                metadataLoader: clientMetadataLoader,
                                replayStore:
                                    try DurableSpaceClientAttestationReplayStore(
                                        controlStore: controlDatabase,
                                        serverKey: serverKey
                                    )
                            )
                    } catch {
                        throw ValidationError(
                            "permissioned client attestation runtime is unavailable"
                        )
                    }
                } else {
                    clientAttestationPolicy =
                        UnavailableSpaceCredentialClientAttestationPolicy()
                }
                let notificationRuntime: ServeNotificationRuntime?
                if let notificationStartupMaterial {
                    notificationRuntime = try ServeNotificationRuntime.load(
                        from: notificationStartupMaterial.rawData,
                        continuityStore: controlDatabase
                    )
                } else {
                    notificationRuntime = nil
                }
                guard !enableNotificationDelivery || notificationRuntime != nil else {
                    throw ValidationError("--enable-notification-delivery requires --notification-config")
                }
                let permissionedRuntime: ServePermissionedRuntime
                var openFederationResolver: SwanDIDDocumentSpaceResolver?
                do {
                    // Managed access checks and open federation resolve service
                    // identifiers through peer-policied DID-document fetching.
                    let notifyServiceResolver: SwanServiceEndpointResolver?
                    let didDocumentFetcher: SwanPeerPinnedDIDDocumentFetcher?
                    do {
                        let policy = try OAuthRemoteFetchPolicy()
                        let fetcher = try SwanPeerPinnedDIDDocumentFetcher(
                            documents: OAuthRemoteDocumentFetcher(
                                policy: policy,
                                transport: try NIOPeerPinnedOAuthDocumentTransport(
                                    maximumTransportTimeout: policy.timeout
                                )
                            ),
                            plcOrigin: managementDeletionPLCConfiguration?.origin
                                ?? PLCClientConfiguration.defaultProductionOrigin
                        )
                        didDocumentFetcher = fetcher
                        notifyServiceResolver = SwanServiceEndpointResolver(documents: fetcher)
                    } catch {
                        didDocumentFetcher = nil
                        notifyServiceResolver = nil
                    }
                    if enableSpacesOpenInterop, didDocumentFetcher == nil {
                        throw ValidationError("--enable-spaces-open-interop requires DID document resolution")
                    }
                    openFederationResolver = enableSpacesOpenInterop
                        ? didDocumentFetcher.map { SwanDIDDocumentSpaceResolver(documents: $0) }
                        : nil
                    permissionedRuntime = try await .compose(
                        local: localSpaceRuntime,
                        notification: notificationRuntime,
                        managingServiceAudience: managingServiceAudience,
                        clientAttestationPolicy: clientAttestationPolicy,
                        serviceEndpointResolver: notifyServiceResolver,
                        spacesOpenInterop: enableSpacesOpenInterop ? .standard : nil,
                        openFederation: openFederationResolver
                    )
                    // Ask the managing app through
                    // com.atproto.managedspace.checkAccess, signed as the
                    // space authority. Without a resolver or local signer,
                    // requests fail as UpstreamFailure rather than becoming
                    // policy denials.
                    if let notifyServiceResolver, let localSpaceRuntime {
                        let policy = try OAuthRemoteFetchPolicy(maximumBodyBytes: 4_096, timeout: 10)
                        await directory.setManagedSpaceAccessChecker(RemoteManagedSpaceAccessChecker(
                            resolver: notifyServiceResolver,
                            signer: localSpaceRuntime.notificationServiceIssuer,
                            policy: policy,
                            transport: NIOPeerPinnedOAuthPostTransport(configuration: try .init(
                                endpointPeers: [:],
                                allowsDynamicPeerSelection: true
                            ))
                        ))
                    }
                } catch {
                    throw ValidationError("permissioned runtime key composition is invalid")
                }
                let notificationRecoveryService: SwanNotificationRecoveryService?
                if enableNotificationDelivery, let notificationRuntime {
                    // Outbox authority calls use service auth; registered sync
                    // endpoints use the opaque token and the same SSRF guard.
                    let serviceIssuer: any SpaceServiceAuthenticationIssuer
                    if let localSpaceRuntime,
                       notificationAccountKEKFile == nil,
                       notificationAccountKEKID == nil,
                       notificationAccountKeyDirectory == nil {
                        serviceIssuer = localSpaceRuntime.notificationServiceIssuer
                    } else {
                        let keyStore: FileAccountKeyStore
                        do {
                            guard let notificationAccountKEKFile else {
                                throw ValidationError("notification account signing key store is unavailable")
                            }
                            let keyConfiguration = try AccountProvisioningSecrets.requiredMountedAccountKeyConfiguration(
                                activeKeyID: notificationAccountKEKID ?? "primary",
                                secretFile: URL(fileURLWithPath: notificationAccountKEKFile)
                            )
                            let keyDirectory = notificationAccountKeyDirectory.map {
                                URL(fileURLWithPath: $0)
                            } ?? dataURL.appending(path: "keys")
                            keyStore = try FileAccountKeyStore(
                                root: keyDirectory,
                                configuration: keyConfiguration
                            )
                        } catch {
                            throw ValidationError("notification account signing key store is unavailable")
                        }
                        do {
                            let passwordHasher = try LibsodiumArgon2idHasher()
                            let accounts = DurableAccountDirectory(
                                store: controlDatabase,
                                passwordHasher: passwordHasher,
                                verificationExecutor: try Argon2idVerificationExecutor(
                                    hasher: passwordHasher
                                )
                            )
                            serviceIssuer = LocalAccountSpaceServiceAuthenticationIssuer(
                                accounts: accounts,
                                keyStore: keyStore
                            )
                        } catch {
                            throw ValidationError("notification account signing runtime is unavailable")
                        }
                    }
                    let outboxDestinations: any SwanSpaceAuthorityNotificationDestinationResolving =
                        openFederationResolver.map {
                            SwanOpenFederationAuthorityNotificationDestinations(
                                configured: notificationRuntime.destinations,
                                resolver: $0
                            )
                        } ?? notificationRuntime.destinations
                    let poster: OAuthBoundedJSONPoster
                    do {
                        let pinned = notificationRuntime.peerPinnedTransportConfiguration
                        poster = .init(
                            policy: try OAuthRemoteFetchPolicy(allowLocalhostDevelopment: true),
                            transport: NIOPeerPinnedOAuthPostTransport(
                                configuration: try .init(
                                    endpointPeers: pinned.endpointPeers,
                                    // Registered sync endpoints have no
                                    // operator pin by construction.
                                    allowsDynamicPeerSelection: true,
                                    additionalTrustRootsPEM: pinned.additionalTrustRootsPEM
                                )
                            )
                        )
                    } catch {
                        throw ValidationError("notification peer-pinned transport is unavailable")
                    }
                    notificationRecoveryService = try await .fromPreopenedDirectory(
                        directory,
                        makeOutboxTransport: { database in
                            HTTPPermissionedSpaceOutboxTransport(
                                destinations: outboxDestinations,
                                announcements: .init(database: database),
                                serviceAuthentication: serviceIssuer,
                                poster: poster
                            )
                        },
                        makeSyncTransport: { _ in
                            HTTPPermissionedSpaceSyncNotificationTransport(
                                poster: poster
                            )
                        }
                    )
                } else {
                    notificationRecoveryService = nil
                }
                let accountEmailXRPC: SwanAccountEmailXRPCServer?
                let emailRecoveryService: SwanAccountEmailRecoveryService?
                if enableEmailRecovery {
                    do {
                        let proofKey = try AccountEmailProofKey(
                            AccountProvisioningSecrets.requiredMounted32ByteSecret(
                                secretFile: URL(fileURLWithPath: emailProofKeyFile!)
                            )
                        )
                        let sender: AccountEmailAddress
                        do {
                            sender = try AccountEmailAddress(emailSender!)
                        } catch {
                            throw ValidationError("--email-sender must be a canonical mailbox")
                        }
                        let delivery = try MailpitSMTPDelivery(
                            host: emailSMTPHost ?? "mailpit",
                            port: emailSMTPPort ?? 1025,
                            sender: sender
                        )
                        let passwordHasher = try LibsodiumArgon2idHasher()
                        let recovery = try AccountEmailRecoveryService(
                            store: controlDatabase,
                            delivery: delivery,
                            proofCodec: AccountEmailProofCodec(key: proofKey),
                            hashExecutor: try Argon2idHashExecutor(
                                hasher: passwordHasher
                            )
                        )
                        let authorizer = try SwanOAuthResourceAuthorizer(
                            publicURL: baseURL,
                            runtime: oauthRuntime,
                            accountControlStore: controlDatabase
                        )
                        accountEmailXRPC = SwanAccountEmailXRPCServer(
                            authorizer: authorizer,
                            recovery: SwanAccountEmailRecoveryXRPCAdapter(
                                service: recovery,
                                store: controlDatabase
                            ),
                            rateLimiter: SwanDurableAccountEmailXRPCRateLimiter(
                                store: controlDatabase,
                                proofCodec: AccountEmailProofCodec(key: proofKey)
                            ),
                            loginClientIdentityPolicy: loginClientIdentityPolicy
                        )
                        emailRecoveryService = try SwanAccountEmailRecoveryService(
                            recovery: recovery,
                            delivery: delivery,
                            workerID: emailWorkerID ?? "swan-email-worker"
                        )
                    } catch let error as ValidationError {
                        throw error
                    } catch {
                        throw ValidationError(
                            "account email recovery runtime is unavailable"
                        )
                    }
                } else {
                    accountEmailXRPC = nil
                    emailRecoveryService = nil
                }

                // One canonical account directory and account-key-backed
                // service-token issuer are shared by the legacy
                // `getServiceAuth` route and the AppView proxy. Construct the
                // issuer before either consumer so production cannot leave
                // the legacy route with its nil default while the proxy has a
                // separate signing authority.
                let accountProgramHasher = try LibsodiumArgon2idHasher()
                // Canonical factor-token storage/verifier is composed for all
                // account authentication consumers, even when the optional
                // portal UI is disabled. A token can never be accepted by a
                // second, UI-only authority.
                let accountProgramFactorTokens = FactorTokenService(store: controlDatabase)
                let accountProgramFactorTokenVerifier:
                    (any AccountLoginFactorTokenVerifying) = accountProgramFactorTokens
                let accountProgramAccounts = DurableAccountDirectory(
                    store: controlDatabase,
                    passwordHasher: accountProgramHasher,
                    verificationExecutor: try Argon2idVerificationExecutor(
                        hasher: accountProgramHasher
                    ),
                    loginAdmissionService: AccountLoginAdmissionService(
                        store: controlDatabase,
                        key: try AccountLoginAdmissionKey(serverKey)
                    ),
                    loginFactorTokenVerifier: accountProgramFactorTokenVerifier,
                    authenticationFactors: controlDatabase
                )
                let accountProxyServiceTokenIssuer: (any SwanProxyServiceTokenIssuing)?
                if let appViewProxyAccountKEKFile {
                    do {
                        let keyStore: FileAccountKeyStore
                        if let validatedLegacySessionStartup,
                           validatedLegacySessionStartup
                               .reusesAppViewProxyConfiguration {
                            // The legacy-session preflight owns this exact
                            // AppView configuration when it is reused.  Keep
                            // one pinned store and never reopen the mounted
                            // KEK file or key-directory pathname.
                            keyStore = validatedLegacySessionStartup.accountKeyStore
                        } else {
                            let keyConfiguration = try AccountProvisioningSecrets
                                .requiredMountedAccountKeyConfiguration(
                                    activeKeyID: appViewProxyAccountKEKID ?? "primary",
                                    secretFile: URL(fileURLWithPath: appViewProxyAccountKEKFile)
                                )
                            let keyDirectory = appViewProxyAccountKeyDirectory.map {
                                URL(fileURLWithPath: $0)
                            } ?? dataURL.appending(path: "keys")
                            keyStore = try withExistingOwnerOnlyKeyDirectory(keyDirectory) {
                                descriptor in
                                try FileAccountKeyStore(
                                    existingRootDirectoryDescriptor: descriptor,
                                    configuration: keyConfiguration
                                )
                            }
                        }
                        accountProxyServiceTokenIssuer = LocalAccountProxyServiceTokenIssuer(
                            accounts: accountProgramAccounts,
                            keyStore: keyStore
                        )
                    } catch {
                        throw ValidationError(
                            "AppView proxy account-key-backed service-token issuer is unavailable"
                        )
                    }
                } else {
                    accountProxyServiceTokenIssuer = nil
                }

                let legacySessionServiceAuthIssuer:
                    (any SwanProxyServiceTokenIssuing)?
                if let legacySessionAccountKeySource {
                    if legacySessionAccountKeySource
                        .reusesAppViewProxyConfiguration {
                        guard let accountProxyServiceTokenIssuer else {
                            throw ValidationError(
                                "legacy-session account-key-backed service-token issuer is unavailable"
                            )
                        }
                        legacySessionServiceAuthIssuer =
                            accountProxyServiceTokenIssuer
                    } else {
                        guard let validatedLegacySessionStartup else {
                            throw ValidationError(
                                "legacy-session account-key-backed service-token issuer is unavailable"
                            )
                        }
                        legacySessionServiceAuthIssuer = Self
                            .makeLegacySessionServiceAuthIssuer(
                                accounts: accountProgramAccounts,
                                keyStore: validatedLegacySessionStartup.accountKeyStore
                            )
                    }
                } else {
                    legacySessionServiceAuthIssuer = nil
                }

                // Legacy (app-password) sessions. Off unless the operator both
                // set the flag and mounted a key — the interlock above already
                // refused to boot on any other combination, so reaching here
                // with the flag set means the key file is named.
                let legacySessionXRPC: SwanLegacySessionXRPCServer?
                if enableLegacySessions {
                    do {
                        guard let validatedLegacySessionStartup else {
                            throw ValidationError(
                                "--enable-legacy-sessions requires a readable owner-only --legacy-session-signing-key-file"
                            )
                        }
                        let credentials = try AppPasswordCredentials()
                        legacySessionXRPC = SwanLegacySessionXRPCServer(
                            sessions: try DurableLegacySessionService(
                                store: controlDatabase,
                                appPasswords: controlDatabase,
                                accountControlStore: controlDatabase,
                                credentials: credentials,
                                // The same identity `/.well-known/did.json` and
                                // `describeServer` publish, so a token's `aud`
                                // names the host that minted it.
                                serviceDID: SwanServiceIdentity(publicURL: baseURL).did,
                                serverKey: validatedLegacySessionStartup.signingKey,
                                identityAdmission: identityAdmission
                            ),
                            credentials: credentials,
                            appPasswords: controlDatabase,
                            // Reuse the directory that backs the account-key
                            // issuer and every other account-program surface.
                            // A second directory would duplicate admission
                            // policy and make service-auth observe a different
                            // lifecycle snapshot than login.
                            accounts: accountProgramAccounts,
                            directory: SwanDurableLegacySessionDirectory(store: controlDatabase),
                            loginClientIdentityPolicy: loginClientIdentityPolicy,
                            serviceAuthIssuer: legacySessionServiceAuthIssuer
                        )
                    } catch let error as ValidationError {
                        throw error
                    } catch {
                        throw ValidationError(
                            "--enable-legacy-sessions requires a readable owner-only "
                                + "--legacy-session-signing-key-file"
                        )
                    }
                } else {
                    legacySessionXRPC = nil
                }
                // Account program shared runtime (Task 7 integration). One
                // durable management-session runtime and one durable account
                // directory back the portal, legacy session, and did:web
                // surfaces so their admission and step-up checks read the
                // same SQLite state.
                let managementSessions = SwanManagementSessionRuntime(
                    store: controlDatabase,
                    preAuthStore: controlDatabase,
                    csrfStore: controlDatabase,
                    preAuthSessionCoordinator: controlDatabase
                )
                // Assigned by the signup runtime below; the portal's
                // lifecycle/delete path fails closed (503) when no public
                // signup policy assembled a lifecycle service.
                var accountLifecycleService: AccountLifecycleService?
                // Account program signup runtime (Task 3). Assembled only for
                // a public signup policy; `closed` keeps the adapter nil so
                // the createAccount route fails closed (503) rather than
                // advertising a signup surface that cannot admit anyone.
                let accountLifecycleXRPC: SwanAccountLifecycleXRPCAdapter?
                var signupEmailOutboxService: SwanSignupEmailOutboxService?
                if resolvedSignupPolicy != .closed {
                    do {
                        guard let accountProgramStartupMaterial,
                              let signupSecret = accountProgramStartupMaterial.signupSecret else {
                            throw ValidationError(
                                "signup runtime requires preflight owner-only mounted secrets"
                            )
                        }
                        let keyConfiguration = accountProgramStartupMaterial.signupAccountKeyConfiguration
                        let keyDirectory = signupAccountKeyDirectory.map {
                            URL(fileURLWithPath: $0)
                        } ?? dataURL.appending(path: "keys")
                        let keyStore = try withExistingOwnerOnlyKeyDirectory(keyDirectory) {
                            descriptor in
                            try FileAccountKeyStore(
                                existingRootDirectoryDescriptor: descriptor,
                                configuration: keyConfiguration
                            )
                        }
                        let passwordHasher = try LibsodiumArgon2idHasher()
                        let proofService = SignupEmailProofService(secret: signupSecret)
                        let extractor = try SocketAddressSignupPeerExtractor(
                            serverSecret: serverKey
                        )
                        let policyService = try SignupPolicyService(
                            policy: resolvedSignupPolicy
                        )
                        let turnstile: TurnstileVerifier?
                        if resolvedSignupPolicy == .openProtected {
                            let secretData = try AccountProvisioningSecrets.requiredMounted32ByteSecret(
                                secretFile: URL(fileURLWithPath: turnstileSecretFile!)
                            )
                            turnstile = try TurnstileVerifier(
                                secret: secretData,
                                hostname: baseURL.host ?? "",
                                action: "signup",
                                transport: try URLSessionTurnstileTransport()
                            )
                        } else {
                            turnstile = nil
                        }
                        let smtpConfiguration = try Self.resolveAuthenticatedSMTPConfiguration(
                            mode: smtpMode,
                            host: emailSMTPHost,
                            port: emailSMTPPort,
                            usernameFile: emailSMTPUsernameFile,
                            passwordFile: emailSMTPPasswordFile,
                            mechanism: smtpMechanism,
                            expectedHostname: emailSMTPExpectedHostname,
                            maximumAttempts: emailSMTPMaxAttempts
                        )
                        let delivery: AuthenticatedSMTPDelivery?
                        if let smtpConfiguration {
                            let transport = try NIOAuthenticatedSMTPTransport()
                            delivery = try AuthenticatedSMTPDelivery(
                                configuration: smtpConfiguration,
                                transport: transport.makeTransport()
                            )
                        } else {
                            delivery = nil
                        }
                        let provisioning = SwanCreateAccountProvisioningProduction(
                            passwordHasher: passwordHasher,
                            keyProvisioner: AccountKeyProvisioner(keyStore: keyStore),
                            sessionRuntime: managementSessions,
                            database: controlDatabase,
                            signupSecret: signupSecret
                        )
                        let signupRateAdmission = try SignupInviteRateAdmission()
                        let service = SignupService(
                            policy: policyService,
                            store: controlDatabase,
                            turnstile: turnstile,
                            rateAdmission: signupRateAdmission,
                            proofVerifier: BoundedSignupEmailProofVerifier(
                                store: controlDatabase
                            ),
                            proofService: proofService
                        )
                        let authorization = SwanCreateAccountAuthorizationPipelineProduction(
                            service: service,
                            extractor: extractor,
                            proofService: proofService,
                            signupSecret: signupSecret
                        )
                        let lifecycle = AccountLifecycleService(
                            store: controlDatabase,
                            deletion: controlDatabase,
                            invites: SignupInviteService(secret: signupSecret),
                            invitePersistence: controlDatabase
                        )
                        accountLifecycleService = lifecycle
                        let capabilityVerifier = try SwanAccountLifecycleCapabilityVerifier(
                            sessionStore: controlDatabase,
                            stepUpStore: controlDatabase
                        )
                        accountLifecycleXRPC = SwanAccountLifecycleXRPCAdapter(
                            lifecycle: lifecycle,
                            provisioning: provisioning,
                            authorization: authorization,
                            capabilityVerifier: capabilityVerifier
                        )
                        if let delivery {
                            let worker = SignupEmailOutboxWorker(
                                store: controlDatabase,
                                deliver: { message in
                                    try await SignupEmailSMTPDeliveryWorker(
                                        proof: proofService,
                                        smtp: delivery
                                    ).deliver(message)
                                }
                            )
                            signupEmailOutboxService = SwanSignupEmailOutboxService(
                                worker: worker,
                                delivery: delivery
                            )
                        }
                    } catch let error as ValidationError {
                        throw error
                    } catch {
                        throw ValidationError("signup runtime is unavailable")
                    }
                } else {
                    accountLifecycleXRPC = nil
                    signupEmailOutboxService = nil
                }
                // Composed unconditionally, and deliberately not behind a
                // flag. Preferences are PDS-owned state that the AppView does
                // not store, so a nil capability here would leave the routes
                // unregistered and hand `putPreferences` to the `/xrpc/**`
                // proxy fallback — discarding the write and disclosing the
                // account's saved feeds, label settings, and muted words to a
                // third party. `SwanOAuthResourceAuthorizer` construction is
                // already a startup precondition above, so this cannot be the
                // thing that fails here.
                let actorPreferencesXRPC = SwanActorPreferencesXRPCServer(
                    authorizer: try SwanOAuthResourceAuthorizer(
                        publicURL: baseURL,
                        runtime: oauthRuntime,
                        accountControlStore: controlDatabase,
                        legacySessions: legacySessionXRPC?.sessions
                    ),
                    store: controlDatabase
                )
                let xrpcPipethrough: SwanXRPCPipethroughServer?
                if disableAppViewProxy {
                    guard appViewDID == nil, appViewURL == nil,
                          appViewServiceFragment == nil,
                          appViewProxyAccountKEKFile == nil,
                          appViewProxyAccountKEKID == nil,
                          appViewProxyAccountKeyDirectory == nil else {
                        throw ValidationError(
                            "AppView proxy options cannot be combined with --disable-appview-proxy"
                        )
                    }
                    xrpcPipethrough = nil
                } else if appViewProxyAccountKEKFile != nil {
                    do {
                        guard let appViewOrigin = URL(
                            string: appViewURL ?? "https://api.bsky.app"
                        ) else {
                            throw ValidationError("--appview-url must be a URL")
                        }
                        let appView = try SwanAppViewConfiguration(
                            did: appViewDID ?? "did:web:api.bsky.app",
                            url: appViewOrigin,
                            serviceFragment: appViewServiceFragment ?? "bsky_appview"
                        )
                        guard let accountProxyServiceTokenIssuer else {
                            throw SwanError.unavailable(
                                "AppView proxy account-key-backed service-token issuer is unavailable"
                            )
                        }
                        // The same resolve → policy-check → pin discipline the
                        // OAuth client-metadata loader uses. It is the only
                        // control stopping a hostile `serviceEndpoint` or
                        // `did:web` host from reaching an internal address.
                        let fetchPolicy = try OAuthRemoteFetchPolicy()
                        let documents = OAuthRemoteDocumentFetcher(
                            policy: fetchPolicy,
                            transport: try NIOPeerPinnedOAuthDocumentTransport(
                                maximumTransportTimeout: fetchPolicy.timeout
                            )
                        )
                        let limits = SwanXRPCPipethroughLimits()
                        xrpcPipethrough = SwanXRPCPipethroughServer(
                            authorizer: try SwanOAuthResourceAuthorizer(
                                publicURL: baseURL,
                                runtime: oauthRuntime,
                                accountControlStore: controlDatabase,
                                legacySessions: legacySessionXRPC?.sessions
                            ),
                            tokens: accountProxyServiceTokenIssuer,
                            sender: SwanPeerPinnedProxySender(
                                policy: fetchPolicy,
                                // A proxied screen resolves one host a dozen
                                // times in parallel. Coalescing those into a
                                // single lookup keeps the four-permit blocking
                                // DNS bound — which fails closed as a 502 —
                                // out of the normal request path.
                                resolver: try CachingOAuthHostnameResolver(
                                    upstream: SystemOAuthHostnameResolver()
                                ),
                                transport: try SwanNIOPeerPinnedProxyTransport(
                                    maximumTransportTimeout: limits.timeout,
                                    // Stated explicitly: the proxy owns its
                                    // inbound body bound rather than silently
                                    // following the transport's default.
                                    maximumRequestBodyBytes:
                                        limits.maximumRequestBodyBytes
                                )
                            ),
                            resolver: SwanServiceEndpointResolver(
                                documents: try SwanPeerPinnedDIDDocumentFetcher(
                                    documents: documents,
                                    // Reuse the operator's configured PLC
                                    // origin when there is one; otherwise the
                                    // single canonical default constant.
                                    plcOrigin: managementDeletionPLCConfiguration?
                                        .origin
                                        ?? PLCClientConfiguration
                                        .defaultProductionOrigin
                                )
                            ),
                            appView: appView,
                            limits: limits
                        )
                    } catch let error as ValidationError {
                        throw error
                    } catch {
                        throw ValidationError("AppView proxy runtime is unavailable")
                    }
                } else {
                    // Not silent: the proxy cannot mint a service token without
                    // account key material, so it stays closed and says so.
                    logger.warning(
                        "AppView proxying is closed: --appview-proxy-account-kek-file is required to mint service tokens, or pass --disable-appview-proxy"
                    )
                    xrpcPipethrough = nil
                }
                let publicFirehoseService: SwanPublicFirehoseSequencerService?
                let publicFirehoseRetentionService: SwanPublicFirehoseRetentionService?
                let publicFirehoseCrawlAnnouncerService: SwanPublicFirehoseCrawlAnnouncerService?
                var publicFirehoseStreamingRuntime: SwanPublicFirehoseStreamingRuntime?
                if enablePublicFirehose {
                    do {
                        let firehoseDatabase = try await SQLiteFirehoseDatabase(
                            dataDirectory: dataURL
                        )
                        let wakeupHub = PublicFirehoseWakeupHub()
                        let sequencer = PublicFirehoseSequencer(
                            accountSource: directory,
                            control: controlDatabase,
                            firehose: firehoseDatabase,
                            wakeup: wakeupHub
                        )
                        publicFirehoseService = SwanPublicFirehoseSequencerService(
                            sequencer: sequencer
                        )
                        publicFirehoseStreamingRuntime = SwanPublicFirehoseStreamingRuntime(
                            database: firehoseDatabase,
                            hub: wakeupHub,
                            limits: .standard,
                            logger: logger
                        )
                        preopenedFirehoseDatabase = firehoseDatabase

                        let (retentionAgeSeconds, retentionAgeOverflowed) =
                            publicFirehoseRetentionAgeHours.multipliedReportingOverflow(by: 3_600)
                        guard !retentionAgeOverflowed else {
                            throw ValidationError(
                                "--public-firehose-retention-age-hours is too large"
                            )
                        }
                        let retentionPolicy: PublicFirehoseRetentionPolicy
                        do {
                            retentionPolicy = try PublicFirehoseRetentionPolicy(
                                maximumAge: .seconds(retentionAgeSeconds),
                                maximumRows: publicFirehoseRetentionMaxRows,
                                maximumBytes: publicFirehoseRetentionMaxBytes
                            )
                        } catch {
                            throw ValidationError(
                                "--public-firehose-retention-age-hours, --public-firehose-retention-max-rows, or --public-firehose-retention-max-bytes is invalid"
                            )
                        }
                        do {
                            publicFirehoseRetentionService = try SwanPublicFirehoseRetentionService(
                                database: firehoseDatabase,
                                hub: wakeupHub,
                                policy: retentionPolicy,
                                interval: .seconds(publicFirehoseRetentionIntervalSeconds),
                                logger: logger
                            )
                        } catch {
                            throw ValidationError(
                                "--public-firehose-retention-interval-seconds must be positive"
                            )
                        }

                        let rawCrawlers = ProcessInfo.processInfo.environment["SWAN_PUBLIC_CRAWLERS"] ?? ""
                        let crawlerOrigins: [URL] = try rawCrawlers
                            .split(separator: ",")
                            .map { $0.trimmingCharacters(in: .whitespaces) }
                            .filter { !$0.isEmpty }
                            .map { raw in
                                guard let url = URL(string: raw),
                                      let scheme = url.scheme, ["http", "https"].contains(scheme),
                                      url.host != nil else {
                                    throw ValidationError("SWAN_PUBLIC_CRAWLERS entry is not a crawler origin URL: \(raw)")
                                }
                                return url
                            }
                        if !crawlerOrigins.isEmpty {
                            guard let announceHost = baseURL.host else {
                                throw ValidationError("--public-url must include a hostname to announce")
                            }
                            let hostname: String
                            if let announcePort = baseURL.port, ![80, 443].contains(announcePort) {
                                hostname = "\(announceHost):\(announcePort)"
                            } else {
                                hostname = announceHost
                            }
                            do {
                                publicFirehoseCrawlAnnouncerService = try SwanPublicFirehoseCrawlAnnouncerService(
                                    control: controlDatabase,
                                    hub: wakeupHub,
                                    transport: try AsyncHTTPClientPublicCrawlTransport(),
                                    crawlers: crawlerOrigins,
                                    hostname: hostname,
                                    logger: logger
                                )
                            } catch {
                                throw ValidationError(
                                    "public firehose requestCrawl announcer is unavailable"
                                )
                            }
                        } else {
                            publicFirehoseCrawlAnnouncerService = nil
                        }
                    } catch let error as ValidationError {
                        throw error
                    } catch {
                        throw ValidationError(
                            "durable public firehose database is unavailable"
                        )
                    }
                } else {
                    guard publicFirehoseRetentionAgeHours == 72,
                          publicFirehoseRetentionMaxRows == 1_000_000,
                          publicFirehoseRetentionMaxBytes == 1_073_741_824,
                          publicFirehoseRetentionIntervalSeconds == 60 else {
                        throw ValidationError(
                            "public firehose retention options require --enable-public-firehose"
                        )
                    }
                    publicFirehoseService = nil
                    publicFirehoseRetentionService = nil
                    publicFirehoseCrawlAnnouncerService = nil
                    publicFirehoseStreamingRuntime = nil
                }
                let managementKeyStore: FileAccountKeyStore?
                if managementNeedsAccountKeyStore {
                    do {
                        guard let managementAccountKEKFile else {
                            throw ValidationError("management account key store is unavailable")
                        }
                        let keyConfiguration = try AccountProvisioningSecrets.requiredMountedAccountKeyConfiguration(
                            activeKeyID: managementAccountKEKID ?? "primary",
                            secretFile: URL(fileURLWithPath: managementAccountKEKFile)
                        )
                        let keyDirectory = managementAccountKeyDirectory.map {
                            URL(fileURLWithPath: $0)
                        } ?? dataURL.appending(path: "keys")
                        managementKeyStore = try FileAccountKeyStore(
                            root: keyDirectory,
                            configuration: keyConfiguration
                        )
                    } catch {
                        throw ValidationError(
                            "management account key store is unavailable"
                        )
                    }
                } else {
                    managementKeyStore = nil
                }
                let managementPLCProvisioning:
                    SwanManagementPLCProvisioningRuntime?
                if enableManagementPLCProvisioning {
                    do {
                        guard let managementKeyStore else {
                            throw SwanError.unavailable(
                                "management account key store is unavailable"
                            )
                        }
                        managementPLCProvisioning = try .init(
                            controlDatabase: controlDatabase,
                            dataDirectory: dataURL,
                            keyStore: managementKeyStore,
                            liveAccountDirectory: directory,
                            lifecycleEmitter: lifecycleEmitter
                        )
                        preopenedManagementProvisioning = managementPLCProvisioning
                    } catch {
                        throw ValidationError("management PLC provisioning runtime is unavailable")
                    }
                } else {
                    managementPLCProvisioning = nil
                }
                let permanentDeletionRuntime:
                    ServeAccountPermanentDeletionRuntime?
                if enableManagementPermanentDeletion {
                    do {
                        guard let managementKeyStore,
                              let managementDeletionPLCConfiguration else {
                            throw SwanError.unavailable(
                                "management permanent deletion runtime is unavailable"
                            )
                        }
                        let runtime = try ServeAccountPermanentDeletionRuntime(
                            controlStore: controlDatabase,
                            dataDirectory: dataURL,
                            keyStore: managementKeyStore,
                            plcConfiguration:
                                managementDeletionPLCConfiguration,
                            liveDirectory: directory
                        )
                        // This is deliberately completed before either
                        // application is built. A pending external side effect
                        // can therefore fail startup, but can never coexist
                        // with a newly accepting public listener.
                        try await runtime.resumePendingJobs(
                            controlStore: controlDatabase
                        )
                        permanentDeletionRuntime = runtime
                    } catch let error as ValidationError {
                        throw error
                    } catch {
                        throw ValidationError(
                            "management permanent deletion runtime is unavailable"
                        )
                    }
                } else {
                    permanentDeletionRuntime = nil
                }
                // Account program production composition (Task 7). The portal,
                // legacy session, and did:web identity surfaces are assembled
                // here from the durable SQLite stores and owner-only mounted
                // secrets; no capability falls back to process memory, and an
                // incomplete secret configuration refuses startup above.
                let accountPortalHTTP: SwanAccountPortalHTTP?
                let didWebIdentityHTTP: SwanDidWebIdentityHTTP?
                var didWebRevalidationService: SwanDidWebRevalidationService?
                if enableAccountPortal {
                    do {
                        guard let didWebSecret = accountProgramStartupMaterial?.didWebSigningKey else {
                            throw ValidationError(
                                "did:web runtime requires a preflight owner-only mounted signing key"
                            )
                        }
                        // did:web identity surface. The reserved signing key is
                        // the mounted secret-derived P-256 key; the document
                        // fetcher is the peer-pinned OAuth transport.
                        let fetchPolicy = try OAuthRemoteFetchPolicy()
                        let documents = OAuthRemoteDocumentFetcher(
                            policy: fetchPolicy,
                            transport: try NIOPeerPinnedOAuthDocumentTransport(
                                maximumTransportTimeout: fetchPolicy.timeout
                            )
                        )
                        let signingKeyProvider = try ServeDidWebSigningKeyProvider(
                            secret: didWebSecret
                        )
                        let reservations = SwanDurableSigningKeyReservationAdapter(
                            store: controlDatabase,
                            provider: signingKeyProvider
                        )
                        let identityService = SwanDidWebIdentityService(
                            reservations: reservations,
                            bindings: controlDatabase,
                            publicPDSURL: baseURL.absoluteString,
                            publicURL: baseURL.absoluteString,
                            gracePeriod: TimeInterval(didWebRevalidationGraceSeconds),
                            replacementAuthorizer: SwanDurableDidWebReplacementAuthorizer(
                                verifier: controlDatabase
                            ),
                            stepUps: SwanDurableStepUpReceiptConsumer(
                                store: controlDatabase
                            ),
                            signingKeyProvider: signingKeyProvider
                        )
                        let didWeb = SwanDidWebIdentityHTTP(
                            service: identityService,
                            sessions: managementSessions,
                            documents: try SwanPeerPinnedDIDDocumentFetcher(
                                documents: documents,
                                plcOrigin: managementDeletionPLCConfiguration?
                                    .origin
                                    ?? PLCClientConfiguration.defaultProductionOrigin
                            ),
                            reservations: reservations,
                            bindings: controlDatabase
                        )
                        didWebIdentityHTTP = didWeb
                        didWebRevalidationService = SwanDidWebRevalidationService(
                            scheduler: didWeb.revalidationScheduler,
                            interval: .seconds(didWebRevalidationIntervalSeconds)
                        )

                        guard let startupMaterial = accountProgramStartupMaterial,
                              let relyingPartyID = baseURL.host else {
                            throw ValidationError(
                                "account MFA runtime requires preflight owner-only mounted material"
                            )
                        }
                        let accountMFA = try SwanAccountPortalMFARuntime(
                            factors: controlDatabase,
                            totpSecrets: controlDatabase,
                            replayStore: controlDatabase,
                            recoveryStore: controlDatabase,
                            webAuthnCredentials: controlDatabase,
                            webAuthnChallenges: controlDatabase,
                            webAuthnEnrollmentStore: controlDatabase,
                            factorTokens: accountProgramFactorTokens,
                            accountKEK: startupMaterial.accountKEK,
                            accountKEKID: startupMaterial.signupAccountKeyConfiguration.activeKeyID,
                            relyingPartyID: relyingPartyID,
                            origin: baseURL.absoluteString
                        )

                        // OAuth browser MFA is the same durable factor runtime
                        // as the portal. Rebind the already-validated OAuth
                        // configuration here, after the account-program
                        // startup material and stores are fully composed.
                        if let existing = localhostOAuthConfiguration {
                            localhostOAuthConfiguration = try SwanLocalhostOAuthConfiguration(
                                issuer: existing.issuer,
                                accounts: existing.accounts,
                                mfaService: SwanOAuthMFAServiceAdapter(factors: controlDatabase, oauthMFA: accountMFA)
                            )
                        }
                        if let existing = authorizationServerConfiguration {
                            authorizationServerConfiguration = try SwanOAuthAuthorizationServerConfiguration(
                                issuer: existing.issuer,
                                protectedResource: baseURL,
                                accounts: existing.accounts,
                                clientMetadataLoader: existing.clientMetadataLoader,
                                scopesSupported: [
                                    "atproto", "transition:generic", "transition:email", "transition:chat.bsky"
                                ],
                                mfaService: SwanOAuthMFAServiceAdapter(factors: controlDatabase, oauthMFA: accountMFA)
                            )
                        }

                        // Portal facade over the same durable stores and the
                        // shared management-session runtime.
                        let portalService = SwanAccountPortalService(
                            accountDirectory: accountProgramAccounts,
                            accountStore: controlDatabase,
                            appPasswords: controlDatabase,
                            appPasswordCredentials: try AppPasswordCredentials(),
                            factors: controlDatabase,
                            lifecycle: accountLifecycleService,
                            identity: SwanAccountPortalIdentityProjectionProduction(
                                didWeb: didWeb
                            ),
                            oauth: SwanAccountPortalOAuthProjectionProduction(
                                store: controlDatabase
                            ),
                            mfa: accountMFA,
                            factorTokens: accountProgramFactorTokens,
                            stepUpReceiptVerifier: SwanAccountPortalDurableStepUpReceiptVerifier(
                                verifier: controlDatabase
                            ),
                            stepUpReceiptConsumer: SwanAccountPortalDurableStepUpReceiptConsumer(
                                store: controlDatabase
                            ),
                            sessions: managementSessions,
                            legacySessions: controlDatabase
                        )
                        accountPortalHTTP = SwanAccountPortalHTTP(
                            configuration: try SwanAccountPortalConfiguration(
                                publicOrigin: baseURL,
                                staticDirectory: accountPortalDirectoryURL,
                                signupPolicy: resolvedSignupPolicy,
                                loginClientIdentityPolicy: loginClientIdentityPolicy
                            ),
                            sessions: managementSessions,
                            service: portalService
                        )
                    } catch let error as ValidationError {
                        throw error
                    } catch {
                        throw ValidationError("account program runtime is unavailable")
                    }
                } else {
                    accountPortalHTTP = nil
                    didWebIdentityHTTP = nil
                }
                // The anonymous `resolveHandle` route's only network reach.
                // Built from the same pinned TXT/`.well-known` resolver that
                // verifies did:web claims, so an attacker-chosen handle cannot
                // steer it at a reserved TLD or a non-public address.
                let foreignHandleResolution: (any SwanForeignHandleResolving)?
                if enableForeignHandleResolution {
                    do {
                        foreignHandleResolution = try SwanForeignHandleResolver(
                            verifier: ATProtocolHandleVerifier(
                                policy: try ATHandleResolutionPolicy.production(),
                                http: try NIOPeerPinnedATHandleHTTPTransport()
                            )
                        )
                    } catch {
                        throw ValidationError(
                            "--enable-foreign-handle-resolution could not build its pinned resolver"
                        )
                    }
                } else {
                    foreignHandleResolution = nil
                }
                let conversationLifecycle: SwanConversationSpaceLifecycle?
                let conversationDeletionService: SwanConversationSpaceDeletionService?
                let conversationPolicy: (any AuthorizedSimpleSpaceCredentialDirectory)?
                let conversationOptions = [conversationSpaceAuthority, conversationSpacePolicyURL,
                                           conversationSpacePolicyAudience, conversationSpacePolicyPeerIP]
                if conversationOptions.contains(where: { $0 != nil }) || conversationSpacePolicyLaboratory {
                    guard let authority = conversationSpaceAuthority,
                          let rawOrigin = conversationSpacePolicyURL, let origin = URL(string: rawOrigin),
                          let audience = conversationSpacePolicyAudience,
                          let rawPeer = conversationSpacePolicyPeerIP, let peer = OAuthIPAddress(literal: rawPeer),
                          let localSpaceRuntime, enableNotificationDelivery, notificationRuntime != nil else {
                        throw ValidationError("conversation Space policy requires all policy options, local account custody, and notification delivery")
                    }
                    _ = try AccountIdentifiers.validateDID(authority)
                    try await directory.requireActivePreopenedAccount(authority)
                    if conversationSpacePolicyLaboratory {
                        guard origin.host == "localhost", peer.isLoopback,
                              !Self.isPubliclyReachableHTTPSOrigin(baseURL),
                              OAuthIPAddress(literal: host)?.isLoopback == true else {
                            throw ValidationError("conversation policy laboratory mode requires localhost, a loopback peer/listener, and a non-public server origin")
                        }
                    }
                    let policy = try OAuthRemoteFetchPolicy(
                        allowLocalhostDevelopment: conversationSpacePolicyLaboratory,
                        networkAllowlist: .init(addresses: conversationSpacePolicyLaboratory ? [peer] : []),
                        maximumBodyBytes: 8192, timeout: 5)
                    let checker = try RemoteConversationSpaceMembershipChecker(
                        origin: origin, audience: audience, signer: localSpaceRuntime.notificationServiceIssuer,
                        policy: policy, transport: NIOPeerPinnedOAuthPostTransport(configuration: try .init(
                            endpointPeers: [origin.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/")): peer])))
                    conversationPolicy = ConversationSpaceCredentialDirectory(local: directory,
                        accounts: directory, authority: authority, membership: checker, lifecycle: directory)
                    conversationLifecycle = SwanConversationSpaceLifecycle(local: directory, lifecycle: directory, remote: checker, membership: checker, notifications: directory, authority: authority)
                    conversationDeletionService = SwanConversationSpaceDeletionService(lifecycle: directory, remote: checker, authority: authority)
                } else {
                    conversationPolicy = nil; conversationLifecycle = nil; conversationDeletionService = nil
                }
                let server = permissionedRuntime.makeServer(
                    profile: loadedProfile,
                    configuration: .init(
                        host: host,
                        port: port,
                        publicURL: baseURL,
                        // Sizes the listener budget and, through it, the
                        // anonymous `subscribeRepos` reservation
                        // `PublicFirehoseSubscriberAdmission` takes as a
                        // quarter of it.
                        maximumConnections: maxConnections,
                        // Spec §4.1: `describeServer.inviteCodeRequired` is
                        // derived as `policy == .inviteRequired` and is never
                        // set independently. The same parsed policy drives the
                        // portal advertisement.
                        inviteCodeRequired: resolvedSignupPolicy == .inviteRequired,
                        publicRouteSurface: publicRouteSurface
                    ),
                    oauthRuntime: oauthRuntime,
                    directory: directory,
                    accountControlStore: controlDatabase,
                    localSpaceRuntime: localSpaceRuntime,
                    publicMutationRuntime: publicMutationRuntime,
                    localhostPARConfiguration: localhostPARConfiguration,
                    localhostOAuthConfiguration: localhostOAuthConfiguration,
                    authorizationServerConfiguration: authorizationServerConfiguration,
                    accountEmailXRPC: accountEmailXRPC,
                    legacySessionXRPC: legacySessionXRPC,
                    actorPreferencesXRPC: actorPreferencesXRPC,
                    accountPortalHTTP: accountPortalHTTP,
                    accountLifecycleXRPC: accountLifecycleXRPC,
                    didWebIdentityHTTP: didWebIdentityHTTP,
                    xrpcPipethrough: xrpcPipethrough,
                    loginClientIdentityPolicy: loginClientIdentityPolicy,
                    publicFirehoseStreaming: publicFirehoseStreamingRuntime,
                    identityAdmission: identityAdmission,
                    foreignHandleResolution: foreignHandleResolution,
                    spaceCredentialPolicyDirectory: conversationPolicy,
                    simpleSpaceLifecycleDirectory: conversationLifecycle,
                    spaceNotificationDirectory: conversationLifecycle,
                    spaceCredentialIssuance: try Self.spaceCredentialIssuance(
                        conversationPolicyEnabled: conversationPolicy != nil
                    )
                )
                guard server.authenticatedGetSpace != nil else {
                    throw ValidationError(
                        "permissioned resource endpoints require HTTPS, or an HTTP public URL and listener both bound to literal loopback on the same port"
                    )
                }
                // Both applications are built before a ServiceGroup starts
                // either one. A bad management bind/config/secret therefore
                // exits rather than silently serving a public-only process to
                // an operator who asked for control-plane access.
                let publicApplication = server.buildApplication(logger: logger)
                let managementApplication: (any ServiceLifecycle.Service)?
                if let managementPort {
                    guard managementPort != port else {
                        throw ValidationError("--management-port must differ from --port")
                    }
                    let managementConfiguration: SwanManagementHTTPConfiguration
                    do {
                        managementConfiguration = try .init(
                            bindAddressLiteral: managementAddress,
                            port: managementPort
                        )
                    } catch {
                        throw ValidationError("management listener must use literal 127.0.0.1 or ::1 and a valid port")
                    }
                    let verifier: OperatorSecretVerifier
                    do {
                        verifier = try OperatorSecretResolver.loadVerifier(
                            secretFile: managementOperatorSecretFile.map { URL(fileURLWithPath: $0) }
                        )
                    } catch {
                        throw ValidationError("management operator secret is unavailable")
                    }
                    let managementFirehoseSync: (any SwanManagementFirehoseSyncing)?
                    if enableManagementFirehoseSync {
                        managementFirehoseSync = SwanManagementFirehoseSyncRuntime(
                            controlStore: controlDatabase,
                            liveAccounts: ServeManagementLiveAccountChecker(directory: directory),
                            emitter: lifecycleEmitter
                        )
                    } else {
                        managementFirehoseSync = nil
                    }
                    let managementServer = SwanManagementHTTPServer(
                        configuration: managementConfiguration,
                        controlStore: controlDatabase,
                        operatorSecretVerifier: verifier,
                        plcProvisioning: managementPLCProvisioning,
                        firehoseSync: managementFirehoseSync,
                        permanentDeletionCoordinator:
                            permanentDeletionRuntime?.coordinator,
                        lifecycleEmitter: lifecycleEmitter
                    )
                    managementApplication = managementServer.buildApplication(
                        logger: Logger(label: "swan.management")
                    )
                } else {
                    guard managementOperatorSecretFile == nil else {
                        throw ValidationError("--management-operator-secret-file requires --management-port")
                    }
                    managementApplication = nil
                }
                logger.info("starting Swan", metadata: [
                    "profile": .string(loadedProfile.id),
                    "publicProfile": .string(publicRouteSurface.profileID),
                    // Declared by the profile, and — separately — the complete
                    // set of public NSIDs this router may install a handler
                    // for. The two differ by
                    // `SwanPublicRouteSurface.outOfProfilePublicMethods`
                    // (`resolveHandle`), which no profile declares. Logging
                    // only the first would understate the served surface by
                    // one, which is the class of thing this line exists to
                    // stop.
                    "publicMethodCount": .string(String(publicRouteSurface.methods.count)),
                    "publicServedMethodCount": .string(
                        String(publicRouteSurface.servedMethodNSIDs.count)
                    ),
                    "address": .string("\(host):\(port)"),
                ])
                var services: [any ServiceLifecycle.Service] = [publicApplication]
                if let conversationDeletionService { services.append(conversationDeletionService) }
                if let localSpaceRuntime {
                    let backfillPLC = try managementDeletionPLCConfiguration
                        ?? ServeNotificationRuntime.kemBackfillPLCConfiguration(notificationStartupMaterial)
                    services.append(SwanAccountKEMBackfillService(
                        control: controlDatabase,
                        keys: localSpaceRuntime.accountKeyStore,
                        rotation: PLCAccountRotationService(
                            controlStore: controlDatabase,
                            accountStoreOpener: SQLitePLCAccountPreparationStoreOpener(dataDirectory: dataURL),
                            keyStore: localSpaceRuntime.accountKeyStore,
                            plcClient: try PLCDirectoryClient(configuration: backfillPLC),
                            lifecycleEmitter: lifecycleEmitter),
                        pdsOrigin: baseURL))
                    logger.info("durable account KEM backfill enabled")
                }
                if permissionedRuntime.notificationConfiguration != nil {
                    logger.info("space notification receiver routes enabled")
                }
                if let notificationRecoveryService {
                    services.append(notificationRecoveryService)
                    logger.info("space notification recovery delivery enabled with peer-pinned NIO transport")
                }
                if let emailRecoveryService {
                    services.append(emailRecoveryService)
                    logger.info("account email recovery delivery enabled with Mailpit SMTP")
                }
                if let signupEmailOutboxService {
                    services.append(signupEmailOutboxService)
                    logger.info("durable signup email outbox worker enabled with authenticated SMTP")
                }
                if let didWebRevalidationService {
                    services.append(didWebRevalidationService)
                    logger.info("durable did:web revalidation scheduler enabled")
                }
                if let publicFirehoseService {
                    services.append(publicFirehoseService)
                    logger.info("durable public firehose sequencing enabled")
                }
                if let publicFirehoseRetentionService {
                    services.append(publicFirehoseRetentionService)
                    logger.info("durable public firehose retention pruning enabled")
                }
                if let publicFirehoseCrawlAnnouncerService {
                    services.append(publicFirehoseCrawlAnnouncerService)
                    logger.info("public firehose requestCrawl announcement enabled")
                }
                if let managementApplication {
                    services.append(managementApplication)
                    logger.info("starting Swan management listener", metadata: [
                        "address": .string("\(managementAddress):\(managementPort!)"),
                    ])
                }
                let serviceGroup = SwanHTTPServiceLifecycle.makeServiceGroup(
                    services: services,
                    logger: logger
                )
                try await serviceGroup.run()
                try await managementPLCProvisioning?.close()
                try await preopenedFirehoseDatabase?.close()
                try await directory.close()
                try await controlDatabase.close()
            } catch {
                if let preopenedManagementProvisioning {
                    try? await preopenedManagementProvisioning.close()
                }
                if let preopenedAccountDirectory {
                    try? await preopenedAccountDirectory.close()
                }
                if let preopenedFirehoseDatabase {
                    try? await preopenedFirehoseDatabase.close()
                }
                try? await controlDatabase.close()
                throw error
            }
        }

        private func loadOAuthServerKey(fromFile path: String?) throws -> Data {
            guard let keyFilePath = path?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !keyFilePath.isEmpty else {
                throw ValidationError("--oauth-server-key-file is required")
            }
            return try readOAuthServerKeyFile(URL(fileURLWithPath: keyFilePath))
        }
    }

    struct Verify: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Verify a pinned Swan artifact")

        @Option(name: .long, help: "Pinned protocol profile JSON")
        var profile: String = "Profiles/permissioned-data-0016-2026-11-12.json"

        @Option(name: .long, help: "Swan package root containing generated wire sources")
        var sourceRoot: String?

        @Option(name: .long, help: "Pinned reference checkout to checksum against")
        var referenceDirectory: String?

        func run() throws {
            let profileURL = URL(fileURLWithPath: profile)
            let report = OfflineProtocolProfileVerifier.verify(
                profileURL: profileURL,
                sourceRoot: sourceRoot.map { URL(fileURLWithPath: $0) }
            )
            guard report.isValid, let profileID = report.profileID else {
                for diagnostic in report.diagnostics {
                    FileHandle.standardError.write(Data((diagnostic.description + "\n").utf8))
                }
                throw ValidationError("offline protocol profile verification failed")
            }
            if let referenceDirectory {
                if profileID == OfflineProtocolProfileVerifier.publicProfileID {
                    try OfflineProtocolProfileVerifier.verifyPinnedPublicLexicons(
                        profileURL: profileURL,
                        referenceRoot: URL(fileURLWithPath: referenceDirectory)
                    )
                } else {
                    try ProtocolProfile.verifyPinnedLexicons(
                        profileURL: profileURL,
                        referenceRoot: URL(fileURLWithPath: referenceDirectory)
                    )
                }
            }
            let suffix = referenceDirectory == nil
                ? "offline artifacts verified"
                : "offline artifacts and pinned lexicons verified"
            print("PROFILE OK: \(profileID) (\(suffix))")
        }
    }

    struct Account: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Inspect or manage a provisioned Swan account",
            subcommands: [
                InstallLocal.self, PreparePLC.self, ActivatePLC.self, RotatePLC.self, Show.self,
                RecoveryCommitKey.self, KEMMethod.self, Deactivate.self, Reactivate.self, DeclareExport.self,
                Delete.self, AdoptRecreatedSpace.self, SpacePolicyReport.self,
            ]
        )

        /// Read-only report of stored space-policy conversion hazards for one
        /// account database. Before v29 it predicts each conversion; afterwards
        /// it combines the recorded log with hazards still present in stored
        /// policy. The database is opened read-only and never migrated.
        struct SpacePolicyReport: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "space-policy-report",
                abstract: "Report stored space-policy conversion hazards (read-only)"
            )

            @Option(name: .long, help: "Required Swan data directory")
            var dataDirectory: String

            @Option(name: .long, help: "Authority account DID")
            var did: String

            func run() async throws {
                let path = SQLiteLayout.accountDatabase(
                    in: URL(fileURLWithPath: dataDirectory, isDirectory: true),
                    did: did
                ).path
                let entries = try await SpacePolicyMigrationReport.scan(databasePath: path)
                let rows: [[String: Any]] = entries.map { entry in
                    var row: [String: Any] = [
                        "space": entry.spaceURI,
                        "owner": entry.owner,
                        "oldReadPolicy": entry.oldReadPolicy,
                        "oldWritePolicy": entry.oldWritePolicy,
                        "oldAppAccess": entry.oldAppAccess,
                        "oldAllowedClients": entry.oldAllowedClients,
                        "droppedMemberCount": entry.droppedMemberCount,
                        "newPolicyType": entry.newPolicyType,
                        "reasons": entry.reasons,
                        "recorded": entry.recorded,
                    ]
                    row["oldReadManagingApp"] = entry.oldReadManagingApp
                    row["oldWriteManagingApp"] = entry.oldWriteManagingApp
                    row["newManagingApp"] = entry.newManagingApp
                    return row
                }
                let data = try JSONSerialization.data(
                    withJSONObject: ["conversions": rows],
                    options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
                )
                print(String(decoding: data, as: UTF8.self))
            }
        }

        /// Emits only the public method for owner-controlled DID documents.
        /// Automatic publication remains confined to the leased PLC backfill.
        struct KEMMethod: AsyncParsableCommand {
            static let configuration = CommandConfiguration(commandName: "kem-method",
                abstract: "Print the public #atproto_kem method for manual DID document publication")
            @Option(name: .long) var dataDirectory: String
            @Option(name: .long) var did: String
            @Option(name: .long) var identityDID: String?
            @Option(name: .long) var operatorSecretFile: String?
            @Option(name: .long) var accountKEKFile: String
            @Option(name: .customLong("account-kek-id")) var accountKEKID: String = "primary"
            @Option(name: .long) var accountKeyDirectory: String?

            func run() async throws {
                _ = try AccountCommandSupport.authorization(secretFilePath: operatorSecretFile)
                let root = URL(fileURLWithPath: dataDirectory)
                let control = try await SQLiteControlDatabase(dataDirectory: root)
                do {
                    guard let account = try await control.account(did: did), account.status == .active else {
                        throw ValidationError("active hosted account required")
                    }
                    let configuration = try AccountProvisioningSecrets.requiredMountedAccountKeyConfiguration(
                        activeKeyID: accountKEKID, secretFile: URL(fileURLWithPath: accountKEKFile))
                    let keys = try FileAccountKeyStore(root: accountKeyDirectory.map { URL(fileURLWithPath: $0) }
                        ?? root.appending(path: "keys"), configuration: configuration)
                    let method = try await AccountKEMKeyProvider(keyStore: keys).verificationMethod(accountDID: did, identityDID: identityDID)
                    try await control.close()
                    try AccountCommandSupport.write(method)
                } catch {
                    try? await control.close()
                    throw AccountCommandSupport.validationError(for: error)
                }
            }
        }

        /// Installs the local, durable half of a Swan account. It deliberately
        /// does not claim PLC registration or remote handle verification: the
        /// command is the offline/recoverable prerequisite for those future
        /// protocol operations, and creates the verified empty public repo.
        struct InstallLocal: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "install-local",
                abstract: "Install a local account, encrypted keys, and an empty public repository"
            )

            @Option(name: .long, help: "Swan data directory; control and per-account databases are created here")
            var dataDirectory: String

            @Option(name: .long, help: "Account DID to install")
            var did: String

            @Option(name: .long, help: "Canonical account handle")
            var handle: String

            @Option(name: .long, help: "Valid repository-v3 revision for the immutable empty public genesis")
            var revision: String

            @Option(name: .long, help: "Owner-only mounted file containing the account password; never accepted literally")
            var passwordFile: String

            @Option(name: .long, help: "Mounted operator-secret file; never accepted as a literal argument")
            var operatorSecretFile: String?

            @Option(name: .long, help: "Owner-only mounted account-KEK file (URL-safe base64)")
            var accountKEKFile: String?

            @Option(name: .customLong("account-kek-id"), help: "Account-KEK identifier written into encrypted envelopes")
            var accountKEKID: String = "primary"

            @Option(name: .long, help: "Protected key-envelope directory; defaults to <data-directory>/keys")
            var accountKeyDirectory: String?

            func run() async throws {
                // Local installation is a management action even though it
                // has no HTTP listener. Resolve the process capability first
                // so an untrusted caller cannot cause key-store mutations.
                _ = try AccountCommandSupport.authorization(
                    secretFilePath: operatorSecretFile
                )
                let password = try AccountProvisioningSecrets.password(
                    secretFile: URL(fileURLWithPath: passwordFile)
                )
                guard let accountKEKFile else {
                    throw ValidationError("--account-kek-file is required")
                }
                let keyConfiguration = try AccountProvisioningSecrets.requiredMountedAccountKeyConfiguration(
                    activeKeyID: accountKEKID,
                    secretFile: URL(fileURLWithPath: accountKEKFile)
                )
                guard !dataDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    throw ValidationError("--data-directory must not be empty")
                }

                let dataURL = URL(fileURLWithPath: dataDirectory)
                let keyURL = accountKeyDirectory.map { URL(fileURLWithPath: $0) }
                    ?? dataURL.appending(path: "keys")
                let control: SQLiteControlDatabase
                let accountDatabase: SQLiteAccountDatabase
                do {
                    control = try await SQLiteControlDatabase(dataDirectory: dataURL)
                    accountDatabase = try await SQLiteAccountDatabase(dataDirectory: dataURL, did: did)
                } catch {
                    throw ValidationError("unable to open Swan account storage")
                }
                do {
                    let keyStore = try FileAccountKeyStore(
                        root: keyURL,
                        configuration: keyConfiguration
                    )
                    let keyProvisioner = AccountKeyProvisioner(keyStore: keyStore)
                    let passwordHasher = try LibsodiumArgon2idHasher()
                    let verificationExecutor = try Argon2idVerificationExecutor(hasher: passwordHasher)
                    let directory = DurableAccountDirectory(
                        store: control,
                        passwordHasher: passwordHasher,
                        verificationExecutor: verificationExecutor,
                        keyProvisioner: keyProvisioner
                    )
                    let installer = LocalAccountProvisioner(
                        directory: directory,
                        publicGenesisStore: accountDatabase,
                        keyProvisioner: keyProvisioner,
                        keyStore: keyStore
                    )
                    let installation = try await installer.install(
                        did: did,
                        handle: handle,
                        password: password,
                        revision: revision
                    )
                    try await accountDatabase.close()
                    try await control.close()
                    try AccountCommandSupport.write(
                        LocalAccountInstallationView(installation: installation)
                    )
                } catch {
                    try? await accountDatabase.close()
                    try? await control.close()
                    throw AccountCommandSupport.validationError(for: error)
                }
            }
        }

        /// Creates the durable, remotely submitted PLC identity package but
        /// deliberately does not install an active account registry row.
        struct PreparePLC: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "prepare-plc",
                abstract: "Prepare and submit a recoverable PLC identity without activating it"
            )

            @Option(name: .long, help: "Swan data directory for control and pending per-account state")
            var dataDirectory: String

            @Option(name: .long, help: "Stable idempotency identifier for this preparation")
            var requestID: String

            @Option(name: .long, help: "Canonical account handle")
            var handle: String

            @Option(name: .long, help: "HTTPS PDS origin recorded in the PLC operation")
            var pdsOrigin: String

            @Option(name: .long, help: "Valid repository-v3 revision for the empty public genesis")
            var repositoryRevision: String

            @Option(name: .long, help: "Owner-supplied DID that must match the staged PLC identity before any PLC submission")
            var expectedDID: String?

            @Option(name: .long, help: "PLC directory origin")
            var plcOrigin: String = PLCClientConfiguration.defaultProductionOrigin.absoluteString

            @Flag(name: .long, help: "Select explicit literal-loopback HTTP PLC laboratory policy")
            var plcLaboratory = false

            @Option(
                name: .customLong("plc-laboratory-allowlisted-host"),
                help: "Explicit Docker/service DNS host allowed for the PLC laboratory origin"
            )
            var plcLaboratoryAllowlistedHost: String?

            @Option(name: .long, help: "Pinned PLC submit compatibility; only did-plc-server-0.0.1 is supported")
            var plcReferenceCompatibility: String?

            @Option(name: .long, help: "Mounted operator-secret file; never accepted as a literal argument")
            var operatorSecretFile: String?

            @Option(name: .long, help: "Owner-only mounted account-KEK file (URL-safe base64)")
            var accountKEKFile: String?

            @Option(name: .customLong("account-kek-id"), help: "Account-KEK identifier written into encrypted envelopes")
            var accountKEKID: String = "primary"

            @Option(name: .long, help: "Protected key-envelope directory; defaults to <data-directory>/keys")
            var accountKeyDirectory: String?

            func run() async throws {
                let preparedConfiguration: (
                    dataURL: URL,
                    pdsOrigin: URL,
                    plc: PLCClientConfiguration
                )
                do {
                    guard !dataDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                        throw SwanError.malformed("--data-directory must not be empty")
                    }
                    guard let suppliedPDSOrigin = URL(string: pdsOrigin) else {
                        throw SwanError.malformed("--pds-origin must be an HTTPS origin")
                    }
                    let canonicalPDSOrigin = try PLCATProfile.canonicalPDSOrigin(
                        suppliedPDSOrigin
                    )
                    guard suppliedPDSOrigin.scheme?.lowercased() == "https",
                          let canonicalPDSURL = URL(string: canonicalPDSOrigin) else {
                        throw SwanError.malformed("--pds-origin must be an HTTPS origin")
                    }
                    try PublicRepositoryGenesisCodec.validateRevision(repositoryRevision)
                    guard let directoryOrigin = URL(string: plcOrigin) else {
                        throw SwanError.malformed("--plc-origin must be a URL")
                    }
                    let responsePolicy: PLCSubmitSuccessResponsePolicy
                    switch plcReferenceCompatibility {
                    case nil:
                        responsePolicy = .strict
                    case PLCSubmitSuccessResponsePolicy.didPLCServer001.rawValue:
                        guard plcLaboratory else {
                            throw SwanError.malformed(
                                "--plc-reference-compatibility requires --plc-laboratory"
                            )
                        }
                        responsePolicy = .didPLCServer001
                    case .some:
                        throw SwanError.malformed(
                            "--plc-reference-compatibility is unsupported"
                        )
                    }
                    let plcConfiguration: PLCClientConfiguration
                    if plcLaboratory {
                        plcConfiguration = try .laboratory(
                            origin: directoryOrigin,
                            submitSuccessResponsePolicy: responsePolicy,
                            allowlistedHost: plcLaboratoryAllowlistedHost
                        )
                    } else {
                        guard plcLaboratoryAllowlistedHost == nil else {
                            throw SwanError.malformed(
                                "--plc-laboratory-allowlisted-host requires --plc-laboratory"
                            )
                        }
                        plcConfiguration = try .production(origin: directoryOrigin)
                    }
                    preparedConfiguration = (
                        URL(fileURLWithPath: dataDirectory),
                        canonicalPDSURL,
                        plcConfiguration
                    )
                } catch {
                    throw AccountCommandSupport.validationError(for: error)
                }

                // Resolve the operator capability before opening either
                // durable storage or the key-envelope store.
                _ = try AccountCommandSupport.authorization(
                    secretFilePath: operatorSecretFile
                )

                guard let accountKEKFile else {
                    throw ValidationError("--account-kek-file is required")
                }
                let keyConfiguration: AccountKeyEncryptionConfiguration
                do {
                    keyConfiguration = try AccountProvisioningSecrets.requiredMountedAccountKeyConfiguration(
                        activeKeyID: accountKEKID,
                        secretFile: URL(fileURLWithPath: accountKEKFile)
                    )
                } catch {
                    throw AccountCommandSupport.validationError(for: error)
                }
                let keyURL = accountKeyDirectory.map { URL(fileURLWithPath: $0) }
                    ?? preparedConfiguration.dataURL.appending(path: "keys")

                let control: SQLiteControlDatabase
                do {
                    control = try await SQLiteControlDatabase(
                        dataDirectory: preparedConfiguration.dataURL
                    )
                } catch {
                    throw ValidationError("unable to open Swan control database")
                }
                var runtime: SwanManagementPLCProvisioningRuntime?
                do {
                    let keyStore = try FileAccountKeyStore(
                        root: keyURL,
                        configuration: keyConfiguration
                    )
                    let createdRuntime = try SwanManagementPLCProvisioningRuntime(
                        controlDatabase: control,
                        dataDirectory: preparedConfiguration.dataURL,
                        keyStore: keyStore
                    )
                    runtime = createdRuntime
                    let prepared = try await createdRuntime.prepare(.init(
                        requestID: requestID,
                        handle: handle,
                        pdsOrigin: preparedConfiguration.pdsOrigin,
                        repositoryRevision: repositoryRevision,
                        expectedDID: expectedDID,
                        plcConfiguration: preparedConfiguration.plc
                    ))
                    try await createdRuntime.close()
                    try await control.close()
                    try AccountCommandSupport.write(
                        PreparedPLCAccountIdentityView(result: prepared)
                    )
                } catch {
                    try? await runtime?.close()
                    try? await control.close()
                    throw AccountCommandSupport.validationError(for: error)
                }
            }
        }

        /// Activates one remotely submitted PLC identity after authenticating
        /// its directory state and proving the recorded AT handle.
        struct ActivatePLC: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "activate-plc",
                abstract: "Activate a submitted PLC identity after directory and handle proof"
            )

            @Option(name: .long, help: "Swan data directory containing the submitted PLC preparation")
            var dataDirectory: String

            @Option(name: .long, help: "Stable idempotency identifier used by prepare-plc")
            var requestID: String

            @Option(name: .long, help: "Owner-only mounted account-password file; never accepted literally")
            var passwordFile: String

            @Option(name: .long, help: "PLC directory origin")
            var plcOrigin: String = PLCClientConfiguration.defaultProductionOrigin.absoluteString

            @Flag(name: .long, help: "Select explicit literal-loopback HTTP PLC laboratory policy")
            var plcLaboratory = false

            @Option(
                name: .customLong("plc-laboratory-allowlisted-host"),
                help: "Explicit Docker/service DNS host allowed for the PLC laboratory origin"
            )
            var plcLaboratoryAllowlistedHost: String?

            @Flag(
                name: .customLong("static-laboratory-handle-proof"),
                help: "Use the explicit no-network handle proof for disposable bootstrap only"
            )
            var useStaticLaboratoryHandleVerifier = false

            @Option(
                name: .long,
                help: "Literal-loopback HTTP origin for laboratory /.well-known/atproto-did proof"
            )
            var handleLaboratoryOrigin: String?

            @Option(name: .long, help: "Mounted operator-secret file; never accepted as a literal argument")
            var operatorSecretFile: String?

            @Option(name: .long, help: "Owner-only mounted account-KEK file (URL-safe base64)")
            var accountKEKFile: String?

            @Option(name: .customLong("account-kek-id"), help: "Account-KEK identifier used by encrypted envelopes")
            var accountKEKID: String = "primary"

            @Option(name: .long, help: "Protected key-envelope directory; defaults to <data-directory>/keys")
            var accountKeyDirectory: String?

            func run() async throws {
                let preparedConfiguration: (
                    dataURL: URL,
                    plc: PLCClientConfiguration,
                    handle: ATHandleResolutionPolicy
                )
                do {
                    guard !dataDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                        throw SwanError.malformed("--data-directory must not be empty")
                    }
                    guard !requestID.isEmpty, requestID.utf8.count <= 128,
                          requestID.utf8.allSatisfy({
                              ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                                  || ($0 >= 97 && $0 <= 122)
                                  || [45, 46, 58, 95].contains($0)
                          }) else {
                        throw SwanError.malformed("--request-id is invalid")
                    }
                    guard !passwordFile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                        throw SwanError.malformed("--password-file must not be empty")
                    }
                    guard !accountKEKID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                        throw SwanError.malformed("--account-kek-id must not be empty")
                    }
                    if let accountKeyDirectory,
                       accountKeyDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        throw SwanError.malformed("--account-key-directory must not be empty")
                    }
                    guard let directoryOrigin = URL(string: plcOrigin) else {
                        throw SwanError.malformed("--plc-origin must be a URL")
                    }

                    let plcConfiguration: PLCClientConfiguration
                    let handlePolicy: ATHandleResolutionPolicy
                    if plcLaboratory {
                        plcConfiguration = try .laboratory(
                            origin: directoryOrigin,
                            allowlistedHost: plcLaboratoryAllowlistedHost
                        )
                        if useStaticLaboratoryHandleVerifier {
                            guard handleLaboratoryOrigin == nil else {
                                throw SwanError.malformed(
                                    "--handle-laboratory-origin cannot be combined with --static-laboratory-handle-proof"
                                )
                            }
                            handlePolicy = try .laboratory(
                                origin: URL(string: "http://127.0.0.1:3000")!
                            )
                        } else {
                            guard let rawHandleOrigin = handleLaboratoryOrigin,
                                  let handleOrigin = URL(string: rawHandleOrigin) else {
                                throw SwanError.malformed(
                                    "--handle-laboratory-origin is required with --plc-laboratory"
                                )
                            }
                            handlePolicy = try .laboratory(origin: handleOrigin)
                        }
                    } else {
                        guard handleLaboratoryOrigin == nil,
                              plcLaboratoryAllowlistedHost == nil,
                              !useStaticLaboratoryHandleVerifier else {
                            throw SwanError.malformed(
                                "laboratory PLC options require --plc-laboratory"
                            )
                        }
                        plcConfiguration = try .production(origin: directoryOrigin)
                        handlePolicy = try .production()
                    }
                    preparedConfiguration = (
                        URL(fileURLWithPath: dataDirectory),
                        plcConfiguration,
                        handlePolicy
                    )
                } catch {
                    throw AccountCommandSupport.validationError(for: error)
                }

                // Authentication must precede password/KEK reads, key-store
                // construction, and every writable database open.
                _ = try AccountCommandSupport.authorization(
                    secretFilePath: operatorSecretFile
                )

                let password: String
                let keyConfiguration: AccountKeyEncryptionConfiguration
                do {
                    password = try AccountProvisioningSecrets.password(
                        secretFile: URL(fileURLWithPath: passwordFile)
                    )
                    guard let accountKEKFile else {
                        throw ValidationError("--account-kek-file is required")
                    }
                    keyConfiguration = try AccountProvisioningSecrets.requiredMountedAccountKeyConfiguration(
                        activeKeyID: accountKEKID,
                        secretFile: URL(fileURLWithPath: accountKEKFile)
                    )
                } catch {
                    throw AccountCommandSupport.validationError(for: error)
                }
                let keyURL = accountKeyDirectory.map { URL(fileURLWithPath: $0) }
                    ?? preparedConfiguration.dataURL.appending(path: "keys")

                let control: SQLiteControlDatabase
                do {
                    control = try await SQLiteControlDatabase(
                        dataDirectory: preparedConfiguration.dataURL
                    )
                } catch {
                    throw ValidationError("unable to open Swan control database")
                }
                var runtime: SwanManagementPLCProvisioningRuntime?
                do {
                    let keyStore = try FileAccountKeyStore(
                        root: keyURL,
                        configuration: keyConfiguration
                    )
                    let createdRuntime = try SwanManagementPLCProvisioningRuntime(
                        controlDatabase: control,
                        dataDirectory: preparedConfiguration.dataURL,
                        keyStore: keyStore
                    )
                    runtime = createdRuntime
                    let installation = try await createdRuntime.activate(.init(
                        requestID: requestID,
                        password: password,
                        plcConfiguration: preparedConfiguration.plc,
                        handlePolicy: preparedConfiguration.handle,
                        useStaticLaboratoryHandleVerifier: useStaticLaboratoryHandleVerifier
                    ))
                    try await createdRuntime.close()
                    try await control.close()
                    try AccountCommandSupport.write(installation)
                } catch {
                    try? await runtime?.close()
                    try? await control.close()
                    throw AccountCommandSupport.validationError(for: error)
                }
            }
        }

        /// Rotates the active account's PLC signing/rotation pair and updates
        /// the durable public identity history. The command never accepts a
        /// private key or password as an argument; encrypted envelopes remain
        /// behind the mounted account-KEK boundary.
        struct RotatePLC: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "rotate-plc",
                abstract: "Rotate an active account's PLC identity keys"
            )

            @Option(name: .long, help: "Swan data directory containing the active account")
            var dataDirectory: String

            @Option(name: .long, help: "Active account DID to rotate")
            var did: String

            @Option(name: .long, help: "PLC directory origin")
            var plcOrigin: String = PLCClientConfiguration.defaultProductionOrigin.absoluteString

            @Flag(name: .long, help: "Select explicit literal-loopback HTTP PLC laboratory policy")
            var plcLaboratory = false

            @Option(name: .long, help: "Pinned PLC submit compatibility; only did-plc-server-0.0.1 is supported")
            var plcReferenceCompatibility: String?

            @Option(name: .long, help: "Mounted operator-secret file; never accepted as a literal argument")
            var operatorSecretFile: String?

            @Option(name: .long, help: "Owner-only mounted account-KEK file (URL-safe base64)")
            var accountKEKFile: String?

            @Option(name: .customLong("account-kek-id"), help: "Account-KEK identifier used by encrypted envelopes")
            var accountKEKID: String = "primary"

            @Option(name: .long, help: "Protected key-envelope directory; defaults to <data-directory>/keys")
            var accountKeyDirectory: String?

            func run() async throws {
                guard !dataDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    throw ValidationError("--data-directory must not be empty")
                }
                guard let directoryOrigin = URL(string: plcOrigin) else {
                    throw ValidationError("--plc-origin must be a URL")
                }
                let responsePolicy: PLCSubmitSuccessResponsePolicy
                switch plcReferenceCompatibility {
                case nil:
                    responsePolicy = .strict
                case PLCSubmitSuccessResponsePolicy.didPLCServer001.rawValue:
                    guard plcLaboratory else {
                        throw ValidationError(
                            "--plc-reference-compatibility requires --plc-laboratory"
                        )
                    }
                    responsePolicy = .didPLCServer001
                case .some:
                    throw ValidationError("--plc-reference-compatibility is unsupported")
                }
                let plcConfiguration: PLCClientConfiguration
                do {
                    plcConfiguration = plcLaboratory
                        ? try .laboratory(
                            origin: directoryOrigin,
                            submitSuccessResponsePolicy: responsePolicy
                        )
                        : try .production(origin: directoryOrigin)
                } catch {
                    throw AccountCommandSupport.validationError(for: error)
                }

                _ = try AccountCommandSupport.authorization(
                    secretFilePath: operatorSecretFile
                )
                guard let accountKEKFile else {
                    throw ValidationError("--account-kek-file is required")
                }
                let keyConfiguration: AccountKeyEncryptionConfiguration
                do {
                    keyConfiguration = try AccountProvisioningSecrets.requiredMountedAccountKeyConfiguration(
                        activeKeyID: accountKEKID,
                        secretFile: URL(fileURLWithPath: accountKEKFile)
                    )
                } catch {
                    throw AccountCommandSupport.validationError(for: error)
                }
                let dataURL = URL(fileURLWithPath: dataDirectory)
                let keyURL = accountKeyDirectory.map { URL(fileURLWithPath: $0) }
                    ?? dataURL.appending(path: "keys")
                let control: SQLiteControlDatabase
                do {
                    control = try await SQLiteControlDatabase(dataDirectory: dataURL)
                } catch {
                    throw ValidationError("unable to open Swan control database")
                }
                let opener = SQLitePLCAccountPreparationStoreOpener(
                    dataDirectory: dataURL
                )
                var accountDatabase: SQLiteAccountDatabase?
                do {
                    guard let account = try await control.account(did: did),
                          account.status.authorizesAccount else {
                        throw ValidationError("account is not active: \(did)")
                    }
                    // The rotation emitter enqueues a control batch only and
                    // never reads the account database, so only the target
                    // account's database is opened; sibling account databases
                    // cannot block rotation of a healthy DID.
                    let openedAccount = try await SQLiteAccountDatabase(
                        dataDirectory: dataURL,
                        did: did
                    )
                    accountDatabase = openedAccount
                    let keyStore = try FileAccountKeyStore(
                        root: keyURL,
                        configuration: keyConfiguration
                    )
                    let service = PLCAccountRotationService(
                        controlStore: control,
                        accountStoreOpener: opener,
                        keyStore: keyStore,
                        plcClient: try PLCDirectoryClient(
                            configuration: plcConfiguration
                        ),
                        lifecycleEmitter: SQLitePublicLifecycleEmitter(
                            control: control,
                            accounts: SingleAccountFirehoseSource(
                                account: PublicFirehoseAccountDatabase(
                                    did: did,
                                    database: openedAccount
                                )
                            )
                        )
                    )
                    let result = try await service.rotate(did: did)
                    try await openedAccount.close()
                    accountDatabase = nil
                    try await opener.close()
                    try await control.close()
                    try AccountCommandSupport.write(
                        try RotatedPLCAccountView(result: result)
                    )
                } catch {
                    try? await accountDatabase?.close()
                    try? await opener.close()
                    try? await control.close()
                    throw AccountCommandSupport.validationError(for: error)
                }
            }
        }

        struct Show: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Show sanitized durable control metadata for one account"
            )

            @Option(name: .long, help: "Required Swan data directory containing control.sqlite")
            var dataDirectory: String

            @Option(name: .long, help: "Account DID to look up")
            var did: String?

            @Option(name: .long, help: "Account handle to look up")
            var handle: String?

            func run() async throws {
                let lookup: AccountOperatorLookup
                switch (did, handle) {
                case let (.some(value), .none):
                    lookup = .did(value)
                case let (.none, .some(value)):
                    lookup = .handle(value)
                default:
                    throw ValidationError("supply exactly one of --did or --handle")
                }
                let view = try await AccountCommandSupport.withService(
                    dataDirectory: dataDirectory
                ) { service in
                    try await service.show(lookup)
                }
                try AccountCommandSupport.write(view)
            }
        }

        /// Exposes only the public P-256 verification bytes that the
        /// permissioned recovery laboratory needs to authenticate a member's
        /// repository commits. The key is not read from an unauthenticated PLC
        /// endpoint: it is derived from the account's durable, signed PLC
        /// history after validating the DID-derived controller, canonical CID
        /// chain, rotation signatures, and exact `atproto` signing-method
        /// binding. Account key envelopes and private signing material are
        /// intentionally never opened by this read-only command.
        struct RecoveryCommitKey: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "recovery-commit-key",
                abstract: "Print the verified public ES256 repository commit key for one active account"
            )

            @Option(name: .long, help: "Required Swan data directory containing control.sqlite")
            var dataDirectory: String

            @Option(name: .long, help: "Active managed account DID")
            var did: String

            func run() async throws {
                guard !dataDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    throw ValidationError("--data-directory must not be empty")
                }
                let canonicalDID: String
                do {
                    canonicalDID = try AccountIdentifiers.validateDID(did)
                } catch {
                    throw ValidationError("--did is not a canonical DID")
                }
                let dataURL = URL(fileURLWithPath: dataDirectory)
                let control: SQLiteControlDatabase
                do {
                    control = try await SQLiteControlDatabase(dataDirectory: dataURL)
                } catch {
                    throw ValidationError("unable to open Swan control database")
                }
                do {
                    guard let account = try await control.account(did: canonicalDID) else {
                        throw ValidationError("account is not managed by this Swan data directory")
                    }
                    guard account.status.authorizesAccount else {
                        throw ValidationError("account is not active")
                    }
                    try await control.close()
                } catch {
                    try? await control.close()
                    throw error
                }

                let database: SQLiteAccountDatabase
                do {
                    database = try await SQLiteAccountDatabase(
                        dataDirectory: dataURL,
                        did: canonicalDID,
                        openMode: .existingPortableExportSource
                    )
                } catch {
                    throw ValidationError("unable to open managed account identity history")
                }
                do {
                    let history = try await database.publicPLCOperationHistory()
                    let identity = try SwanPublicPLCGenesisVerifier().verifyIdentityHistory(
                        history,
                        expectedDID: canonicalDID
                    )
                    guard case let .p256(publicKey) = try PLCDIDKeyCodec.decode(
                        identity.signingDIDKey
                    ) else {
                        throw ValidationError("verified atproto signing method is not ES256")
                    }
                    try await database.close()
                    // This is deliberately a bare public value, rather than a
                    // JSON account projection: the caller receives no DID,
                    // handle, key generation, path, or private-key metadata.
                    print("ES256:" + publicKey.x963Representation.base64URLEncodedString())
                } catch let error as ValidationError {
                    try? await database.close()
                    throw error
                } catch {
                    try? await database.close()
                    throw ValidationError("verified account PLC identity is unavailable")
                }
            }
        }

        struct Deactivate: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Deactivate a provisioned Swan account"
            )

            @Option(name: .long, help: "Required Swan data directory containing control.sqlite")
            var dataDirectory: String

            @Option(name: .long, help: "Account DID to deactivate")
            var did: String

            @Option(name: .long, help: "Mounted operator-secret file; never accepted as a literal argument")
            var operatorSecretFile: String?

            func run() async throws {
                let authorization = try AccountCommandSupport.authorization(
                    secretFilePath: operatorSecretFile
                )
                let view = try await AccountCommandSupport.withService(
                    dataDirectory: dataDirectory
                ) { service in
                    try await service.deactivate(did: did, authorization: authorization)
                }
                try AccountCommandSupport.write(view)
            }
        }

        struct Reactivate: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Reactivate a provisioned Swan account"
            )

            @Option(name: .long, help: "Required Swan data directory containing control.sqlite")
            var dataDirectory: String

            @Option(name: .long, help: "Account DID to reactivate")
            var did: String

            @Option(name: .long, help: "Mounted operator-secret file; never accepted as a literal argument")
            var operatorSecretFile: String?

            func run() async throws {
                let authorization = try AccountCommandSupport.authorization(
                    secretFilePath: operatorSecretFile
                )
                let view = try await AccountCommandSupport.withService(
                    dataDirectory: dataDirectory
                ) { service in
                    try await service.reactivate(did: did, authorization: authorization)
                }
                try AccountCommandSupport.write(view)
            }
        }

        /// Idempotent recovery path for the narrow interval after an archive
        /// was durably published but before its digest reached control.sqlite.
        struct DeclareExport: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "declare-export",
                abstract: "Record the digest of an already verified portable export"
            )

            @Option(name: .long, help: "Required Swan data directory containing control.sqlite")
            var dataDirectory: String

            @Option(name: .long, help: "Active account DID")
            var did: String

            @Option(name: .long, help: "sha256:<64 lowercase hex> manifest digest")
            var manifestReference: String

            @Option(name: .long, help: "Mounted operator-secret file; never accepted as a literal argument")
            var operatorSecretFile: String?

            func run() async throws {
                let authorization = try AccountCommandSupport.authorization(
                    secretFilePath: operatorSecretFile
                )
                let view = try await AccountCommandSupport.withService(
                    dataDirectory: dataDirectory
                ) { service in
                    try await service.declareExport(
                        did: did,
                        manifestReference: manifestReference,
                        authorization: authorization
                    )
                }
                try AccountCommandSupport.write(view)
            }
        }

        struct Delete: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Permanently deactivate an account and retain its declared tombstone"
            )

            @Option(name: .long, help: "Required Swan data directory containing control.sqlite")
            var dataDirectory: String

            @Option(name: .long, help: "Account DID to delete")
            var did: String

            @Option(name: .long, help: "Mounted operator-secret file; never accepted as a literal argument")
            var operatorSecretFile: String?

            @Option(name: .long, help: "Optional bounded tombstone reason")
            var tombstoneReason: String?

            @Option(name: .long, help: "Optional sha256:<64 lowercase hex> portable-export manifest reference")
            var exportReference: String?

            @Option(name: .long, help: "PLC directory origin")
            var plcOrigin: String?

            @Flag(name: .long, help: "Select explicit literal-loopback HTTP PLC laboratory policy")
            var plcLaboratory = false

            @Option(
                name: .customLong("plc-laboratory-allowlisted-host"),
                help: "Explicit Docker/service DNS host allowed for the PLC laboratory origin"
            )
            var plcLaboratoryAllowlistedHost: String?

            @Option(name: .long, help: "Pinned PLC submit compatibility; only did-plc-server-0.0.1 is supported")
            var plcReferenceCompatibility: String?

            @Option(name: .long, help: "Owner-only mounted account-KEK file (URL-safe base64)")
            var accountKEKFile: String?

            @Option(name: .customLong("account-kek-id"), help: "Active account-KEK identifier used by encrypted envelopes")
            var accountKEKID: String = "primary"

            @Option(name: .long, help: "Protected key-envelope directory; defaults to <data-directory>/keys")
            var accountKeyDirectory: String?

            func run() async throws {
                guard !dataDirectory.trimmingCharacters(
                    in: .whitespacesAndNewlines
                ).isEmpty else {
                    throw ValidationError("--data-directory must not be empty")
                }
                guard !accountKEKID.trimmingCharacters(
                    in: .whitespacesAndNewlines
                ).isEmpty,
                      accountKeyDirectory.map({
                          !$0.trimmingCharacters(
                              in: .whitespacesAndNewlines
                          ).isEmpty
                      }) ?? true else {
                    throw ValidationError(
                        "account deletion key-store options are invalid"
                    )
                }
                let plcConfiguration =
                    try makePermanentDeletionPLCConfiguration(
                        origin: plcOrigin,
                        laboratory: plcLaboratory,
                        laboratoryAllowlistedHost:
                            plcLaboratoryAllowlistedHost,
                        referenceCompatibility:
                            plcReferenceCompatibility
                    )
                // Operator authorization precedes every mounted-secret read,
                // encrypted-key-store construction, and writable database
                // open.
                let authorization = try AccountCommandSupport.authorization(
                    secretFilePath: operatorSecretFile
                )
                guard let accountKEKFile else {
                    throw ValidationError("--account-kek-file is required")
                }
                let keyConfiguration: AccountKeyEncryptionConfiguration
                do {
                    keyConfiguration = try AccountProvisioningSecrets
                        .requiredMountedAccountKeyConfiguration(
                            activeKeyID: accountKEKID,
                            secretFile: URL(fileURLWithPath: accountKEKFile)
                        )
                } catch {
                    throw AccountCommandSupport.validationError(for: error)
                }
                let dataURL = URL(fileURLWithPath: dataDirectory)
                let keyURL = accountKeyDirectory.map {
                    URL(fileURLWithPath: $0)
                } ?? dataURL.appending(path: "keys")
                let control: SQLiteControlDatabase
                do {
                    control = try await SQLiteControlDatabase(
                        dataDirectory: dataURL
                    )
                } catch {
                    throw ValidationError(
                        "unable to open Swan control database"
                    )
                }
                do {
                    let keyStore = try FileAccountKeyStore(
                        root: keyURL,
                        configuration: keyConfiguration
                    )
                    let runtime = try ServeAccountPermanentDeletionRuntime(
                        controlStore: control,
                        dataDirectory: dataURL,
                        keyStore: keyStore,
                        plcConfiguration: plcConfiguration,
                        liveDirectory: nil
                    )
                    let service = AccountOperatorService(
                        store: control,
                        permanentDeletionCoordinator: runtime.coordinator
                    )
                    let view = try await service.delete(
                        did: did,
                        tombstoneReason: tombstoneReason,
                        exportReference: exportReference,
                        authorization: authorization
                    )
                    try await control.close()
                    try AccountCommandSupport.write(view)
                } catch {
                    try? await control.close()
                    throw AccountCommandSupport.validationError(for: error)
                }
            }
        }
    }

    struct Lab: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Validate and record sanitized Compose laboratory scenarios",
            subcommands: [Validate.self, Matrix.self, Scenario.self, Semantic.self, StatefulFaultMatrix.self, PermissionedReplicaHead.self, ImportPublic.self, SyncPermissioned.self, RecoverPermissioned.self, Live.self, Forum.self],
            defaultSubcommand: Validate.self
        )

        struct SyncPermissioned: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "sync-permissioned",
                abstract: "Fetch, verify, and durably apply one permissioned incremental interval"
            )

            @Option(name: .customLong("receiver-did"))
            var receiverDID: String
            @Option(name: .long)
            var repository: String
            @Option(name: .long)
            var space: String
            @Option(name: .long)
            var dataDirectory: String
            @Option(name: .customLong("source-url"))
            var sourceURL: String = ""
            @Option(name: .customLong("authority-url"))
            var authorityURL: String = ""
            @Option(name: .customLong("source-auth"))
            var sourceAuth: String = "oauth"
            @Option(name: .customLong("source-token-file"))
            var sourceTokenFile: String?
            @Option(name: .customLong("source-handle-env"))
            var sourceHandleEnvironment = "SWAN_LAB_PRODUCER_HANDLE"
            @Option(name: .customLong("source-password-file"))
            var sourcePasswordFile: String?
            @Option(name: .customLong("source-client-id"))
            var sourceClientID: String = ""
            @Option(name: .customLong("source-redirect-uri"))
            var sourceRedirectURI: String = ""
            @Option(name: .long, parsing: .upToNextOption)
            var scope: [String] = ["atproto"]
            @Option(name: .customLong("permissioned-commit-key-env"), help: "Compatibility option only; native reads use SWAN_LAB_KEM_KEYS_FILE or SWAN_LAB_KEM_PUBLIC_KEY")
            var permissionedCommitKeyEnvironment =
                "SWAN_LAB_PERMISSIONED_COMMIT_KEY"
            @Option(name: .customLong("request-id"))
            var requestID: String = ""
            @Option(name: .customLong("request-sequence"))
            var requestSequence: UInt64 = 1
            @Flag(
                name: .customLong("verify-exact-duplicate-replay"),
                help: "Apply the same authenticated batch twice and require an exact-duplicate durable replay witness"
            )
            var verifyExactDuplicateReplay = false
            @Flag(
                name: .customLong("full-car-recovery"),
                inversion: .prefixedNo,
                help: "Compatibility flag name; perform verified full-STAR replacement when incremental history is unavailable"
            )
            var fullCARRecovery = true
            @Option(name: .long)
            var output = "artifacts/live/permissioned-incremental-sync.json"
            @Option(name: .customLong("request-timeout-seconds"))
            var requestTimeoutSeconds: Double = 15
            @Flag(
                name: .customLong("fail-on-failure"),
                inversion: .prefixedNo
            )
            var failOnFailure = true

            func run() async throws {
                let receiver = try canonicalDID(receiverDID, option: "receiver-did")
                let repository = try canonicalDID(repository, option: "repository")
                let space: SpaceURI
                do { space = try SpaceURI(self.space) }
                catch { throw ValidationError("--space is not a valid space URI") }
                guard requestSequence > 0 else {
                    throw ValidationError("--request-sequence must be positive")
                }
                guard requestTimeoutSeconds > 0,
                      requestTimeoutSeconds <= 120,
                      requestTimeoutSeconds.isFinite else {
                    throw ValidationError("--request-timeout-seconds is invalid")
                }
                let requestID = try normalizedRequestID(self.requestID)
                let sourceAuth = self.sourceAuth.trimmingCharacters(
                    in: .whitespacesAndNewlines
                ).lowercased()
                guard sourceAuth == "bearer" || sourceAuth == "oauth" else {
                    throw ValidationError("--source-auth must be bearer or oauth")
                }
                let dataURL = URL(fileURLWithPath: dataDirectory)
                try await requireActiveManagedAccount(
                    did: receiver,
                    dataDirectory: dataURL
                )
                // Native reads authenticate with the dedicated per-request KEM exchange.
                let key: PermissionedDataJWTVerificationKey? = nil
                let sourceEndpoint = try LabLiveSupport.url(
                    explicit: sourceURL,
                    environment: "SWAN_LAB_PRODUCER_URL",
                    fallback: "https://pds.test"
                )
                let authorityEndpoint = try LabLiveSupport.url(
                    explicit: authorityURL,
                    environment: "SWAN_LAB_CONSUMER_URL",
                    fallback: "https://swan.test"
                )
                let member = try await LabLiveSupport.host(
                    label: "member", url: sourceEndpoint, auth: sourceAuth,
                    tokenFile: sourceTokenFile,
                    handleEnvironment: sourceHandleEnvironment,
                    passwordFile: sourcePasswordFile,
                    clientID: sourceClientID,
                    redirectURI: sourceRedirectURI, scopes: scope,
                    timeout: requestTimeoutSeconds,
                    permissionedCommitVerificationKey: key
                )
                let authority = try await LabLiveSupport.host(
                    label: "authority", url: authorityEndpoint, auth: "none",
                    tokenFile: nil,
                    handleEnvironment: "SWAN_UNUSED",
                    passwordFile: nil, clientID: "",
                    redirectURI: "", scopes: scope,
                    timeout: requestTimeoutSeconds,
                    permissionedCommitVerificationKey: nil
                )
                let credential = try await SpaceCredentialBroker(
                    member: member.client,
                    authority: authority.client
                ).exchange(
                    space: space,
                    memberAuthorization: member.authorization,
                    memberAuthorizationProvider: member.authorizationProvider
                )
                let source = LiveInteropHost(
                    label: "source", client: member.client,
                    authorization: .spaceCredential(credential),
                    permissionedCommitVerificationKey: key,
                    permissionedKEMKeyProvider: try LabLiveSupport.kemKeyProvider()
                )
                let database = try await SQLiteAccountDatabase(
                    dataDirectory: dataURL,
                    did: receiver,
                    openMode: .existingManaged
                )
                let target = try PermissionedRemoteReplicaTarget(
                    receiverDID: receiver,
                    space: space,
                    repositoryDID: repository
                )
                let prior = try await database.permissionedRemoteReplicaHead(
                    target: target
                )
                let applyAuthorized:
                    PermissionedRemoteReplicaIncrementalHTTPOrchestrator
                    .PublicationAuthorization = { operation in
                        let control = try await SQLiteControlDatabase(
                            dataDirectory: dataURL
                        )
                        do {
                            let result = try await control
                                .withActiveAccountAuthorization(
                                    did: receiver,
                                    operation: operation
                                )
                            try await control.close()
                            return result
                        } catch {
                            try? await control.close()
                            throw error
                        }
                    }
                let authorization:
                    PermissionedRemoteReplicaIncrementalHTTPOrchestrator
                    .PublicationAuthorization = { operation in
                        let first = try await applyAuthorized(operation)
                        guard verifyExactDuplicateReplay else { return first }
                        guard case let .applied(firstResult) = first else {
                            throw SwanError.unavailable(
                                "exact duplicate replay proof did not begin with an applied batch"
                            )
                        }
                        let second = try await applyAuthorized(operation)
                        guard case let .exactDuplicate(secondResult) = second,
                              secondResult == firstResult else {
                            throw SwanError.unavailable(
                                "exact duplicate replay proof did not return the original durable result"
                            )
                        }
                        return second
                    }
                let orchestrator =
                    PermissionedRemoteReplicaIncrementalHTTPOrchestrator(
                        source: source,
                        store: database,
                        publicationAuthorization: authorization
                    )
                let outcome: PermissionedRemoteReplicaIncrementalSyncOutcome
                do {
                    outcome = try await orchestrator.synchronize(
                        target: target,
                        requestID: requestID,
                        requestSequence: requestSequence,
                        appliedAt: Int64(Date().timeIntervalSince1970)
                    )
                } catch {
                    try? await database.close()
                    throw error
                }
                var outcomeCode = outcome.code
                var passed = outcome.passed
                if case .fullCARRecoveryRequired = outcome,
                   fullCARRecovery {
                    do {
                        let limits = SpaceCARRecoveryLimits.standard
                        let temporaryDirectory = FileManager.default
                            .temporaryDirectory.appending(
                                path: "swan-permissioned-sync-\(UUID().uuidString)",
                                directoryHint: .isDirectory
                            )
                        try FileManager.default.createDirectory(
                            at: temporaryDirectory,
                            withIntermediateDirectories: false,
                            attributes: [.posixPermissions: 0o700]
                        )
                        defer {
                            try? FileManager.default.removeItem(
                                at: temporaryDirectory
                            )
                        }
                        let spoolAdmission = try PublicRepositorySpoolAdmission(
                            maximumGlobalBytes: limits.maximumCARBytes,
                            maximumPerAccountBytes: limits.maximumCARBytes
                        )
                        let recoveryAuthorization:
                            PermissionedRemoteReplicaRecoveryOrchestrator
                            .PublicationAuthorization = { operation in
                                let control = try await SQLiteControlDatabase(
                                    dataDirectory: dataURL
                                )
                                do {
                                    let result = try await control
                                        .withActiveAccountAuthorization(
                                            did: receiver,
                                            operation: operation
                                        )
                                    try await control.close()
                                    return result
                                } catch {
                                    try? await control.close()
                                    throw error
                                }
                            }
                        _ = try await LiveInteropRunner
                            .recoverPermissionedRepository(
                                target: target,
                                requestID: "\(requestID)-full-car",
                                sourceHost: source,
                                receiverDatabase: database,
                                expiresAt:
                                    Int64(Date().timeIntervalSince1970) + 300,
                                temporaryDirectory: temporaryDirectory,
                                spoolAdmission: spoolAdmission,
                                limits: limits,
                                publicationAuthorization: recoveryAuthorization,
                                now: { Int64(Date().timeIntervalSince1970) }
                            )
                        outcomeCode = "full_car_applied"
                        passed = true
                    } catch {
                        try? await database.close()
                        throw error
                    }
                }
                let final = try await database.permissionedRemoteReplicaHead(
                    target: target
                )
                try await database.close()
                let replayWitness: ExactDuplicateReplayWitness?
                if verifyExactDuplicateReplay {
                    guard case let .exactDuplicate(result) = outcome else {
                        throw SwanError.unavailable(
                            "exact duplicate replay proof did not complete"
                        )
                    }
                    replayWitness = ExactDuplicateReplayWitness(
                        applyAttempts: 2,
                        firstOutcome: "applied",
                        secondOutcome: "exact_duplicate",
                        requestDigest: Hex.encode(result.requestDigest)
                    )
                } else {
                    replayWitness = nil
                }
                let artifact = Artifact(
                    requestSequence: requestSequence,
                    outcome: outcomeCode,
                    priorRevision: prior?.wireRevision.toString(),
                    finalRevision: final?.wireRevision.toString(),
                    finalCommitment: final.map { Hex.encode($0.commitment) },
                    exactDuplicateReplay: replayWitness,
                    status: passed ? "passed" : "failed"
                )
                let outputURL = URL(fileURLWithPath: output)
                try FileManager.default.createDirectory(
                    at: outputURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                try encoder.encode(artifact).write(to: outputURL, options: .atomic)
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: outputURL.path
                )
                print("PERMISSIONED INCREMENTAL ARTIFACT WRITTEN: \(outputURL.path) status=\(artifact.status)")
                guard !failOnFailure || artifact.status == "passed" else {
                    throw ValidationError(
                        "permissioned incremental sync did not pass; inspect \(outputURL.lastPathComponent)"
                    )
                }
            }

            private func canonicalDID(
                _ value: String,
                option: String
            ) throws -> String {
                do { return try AccountIdentifiers.validateDID(value) }
                catch { throw ValidationError("--\(option) is not a canonical DID") }
            }

            private func normalizedRequestID(_ value: String) throws -> String {
                let value = value.isEmpty
                    ? "incremental-\(UUID().uuidString.lowercased())"
                    : try LabLiveSupport.identifier(value, label: "request ID")
                guard value.utf8.count <= 128 else {
                    throw ValidationError("request ID must not exceed 128 bytes")
                }
                return value
            }

            private func requireActiveManagedAccount(
                did: String,
                dataDirectory: URL
            ) async throws {
                let control = try await SQLiteControlDatabase(
                    dataDirectory: dataDirectory
                )
                do {
                    guard let account = try await control.account(did: did) else {
                        throw ValidationError(
                            "receiver account is not managed by this Swan data directory"
                        )
                    }
                    guard account.status.authorizesAccount else {
                        throw ValidationError("receiver account is not active")
                    }
                    try await control.close()
                } catch {
                    try? await control.close()
                    throw error
                }
            }

            private struct Artifact: Encodable {
                let requestSequence: UInt64
                let outcome: String
                let priorRevision: String?
                let finalRevision: String?
                let finalCommitment: String?
                let exactDuplicateReplay: ExactDuplicateReplayWitness?
                let status: String
            }

            private struct ExactDuplicateReplayWitness: Encodable {
                let applyAttempts: Int
                let firstOutcome: String
                let secondOutcome: String
                let requestDigest: String
            }
        }

        struct RecoverPermissioned: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "recover-permissioned",
                abstract: "Stream, verify, and durably install a permissioned repository STAR snapshot"
            )

            @Option(name: .customLong("receiver-did"), help: "Managed receiver account DID")
            var receiverDID: String

            @Option(name: .long, help: "Repository DID hosted by the source")
            var repository: String

            @Option(name: .long, help: "Permissioned space URI")
            var space: String

            @Option(name: .long, help: "Swan data directory containing the receiver database")
            var dataDirectory: String

            @Option(name: .long, help: "Scenario identifier used only in the sanitized artifact")
            var name: String = "permissioned-recovery"

            @Option(name: .customLong("source-url"), help: "Permissioned repository/member host URL")
            var sourceURL: String = ""

            @Option(name: .customLong("authority-url"), help: "Space authority host URL")
            var authorityURL: String = ""

            @Option(name: .customLong("source-auth"), help: "Source/member auth: bearer or oauth")
            var sourceAuth: String = "oauth"

            @Option(name: .customLong("source-token-file"), help: "Owner-only file containing the source/member bearer token")
            var sourceTokenFile: String?

            @Option(name: .customLong("source-handle-env"), help: "Source/member OAuth handle environment variable")
            var sourceHandleEnvironment: String = "SWAN_LAB_PRODUCER_HANDLE"

            @Option(name: .customLong("source-password-file"), help: "Owner-only file containing the source/member OAuth password")
            var sourcePasswordFile: String?

            @Option(name: .customLong("source-client-id"), help: "Source/member OAuth client metadata URL")
            var sourceClientID: String = ""

            @Option(name: .customLong("source-redirect-uri"), help: "Source/member OAuth redirect URI")
            var sourceRedirectURI: String = ""

            @Option(name: .long, parsing: .upToNextOption, help: "OAuth scope requested from the source/member; repeatable")
            var scope: [String] = ["atproto"]

            @Option(name: .long, help: "Retained-operation cursor that must produce full_repo_recovery_required")
            var since: String

            @Flag(
                name: .customLong("allow-full-car-fallback"),
                help: "Compatibility flag name; allow an explicitly requested full-STAR install when listRepoOps succeeds without a retention-gap error"
            )
            var allowFullCARFallback = false

            @Option(
                name: .customLong("permissioned-commit-key-env"),
                help: "Compatibility option only; native reads use SWAN_LAB_KEM_KEYS_FILE or SWAN_LAB_KEM_PUBLIC_KEY"
            )
            var permissionedCommitKeyEnvironment =
                "SWAN_LAB_PERMISSIONED_COMMIT_KEY"

            @Option(name: .customLong("request-id"), help: "Optional idempotency key prefix for the valid and corrupted installs")
            var requestID: String = ""

            @Flag(
                name: .customLong("require-prior-head"),
                help: "Require an existing durable receiver head and prove a generation-advancing CAS replacement"
            )
            var requirePriorHead = false

            @Option(name: .long, help: "Destination for the sanitized recovery artifact")
            var output: String =
                "artifacts/live/permissioned-recovery.json"

            @Option(name: .long, help: "Per-request timeout in seconds")
            var requestTimeoutSeconds: Double = 15

            @Flag(
                name: .customLong("fail-on-failure"),
                inversion: .prefixedNo,
                help: "Return non-zero when recovery acceptance does not pass (default)"
            )
            var failOnFailure = true

            func run() async throws {
                let canonicalReceiver: String
                do {
                    canonicalReceiver = try AccountIdentifiers.validateDID(
                        receiverDID
                    )
                } catch {
                    throw ValidationError("--receiver-did is not a canonical DID")
                }
                let canonicalRepository: String
                do {
                    canonicalRepository = try AccountIdentifiers.validateDID(
                        repository
                    )
                } catch {
                    throw ValidationError("--repository is not a canonical DID")
                }
                let parsedSpace: SpaceURI
                do {
                    parsedSpace = try SpaceURI(space)
                } catch {
                    throw ValidationError("--space is not a valid space URI")
                }
                let sinceRevision: TID
                do {
                    sinceRevision = try TID(tidString: since)
                } catch {
                    throw ValidationError("--since is not a canonical TID")
                }
                guard !dataDirectory.trimmingCharacters(
                    in: .whitespacesAndNewlines
                ).isEmpty else {
                    throw ValidationError("--data-directory must not be empty")
                }
                let scenario = try LabLiveSupport.identifier(
                    name,
                    label: "scenario"
                )
                let sourceEndpoint = try LabLiveSupport.url(
                    explicit: sourceURL,
                    environment: "SWAN_LAB_PRODUCER_URL",
                    fallback: "https://pds.test"
                )
                let authorityEndpoint = try LabLiveSupport.url(
                    explicit: authorityURL,
                    environment: "SWAN_LAB_CONSUMER_URL",
                    fallback: "https://swan.test"
                )
                guard requestTimeoutSeconds > 0,
                      requestTimeoutSeconds <= 120,
                      requestTimeoutSeconds.isFinite else {
                    throw ValidationError(
                        "--request-timeout-seconds is invalid"
                    )
                }
                let normalizedSourceAuth = sourceAuth.trimmingCharacters(
                    in: .whitespacesAndNewlines
                ).lowercased()
                guard normalizedSourceAuth == "bearer"
                    || normalizedSourceAuth == "oauth" else {
                    throw ValidationError(
                        "--source-auth must be bearer or oauth"
                    )
                }
                let verificationKey: PermissionedDataJWTVerificationKey? = nil
                let requestPrefix: String
                if requestID.isEmpty {
                    requestPrefix = "recover-\(UUID().uuidString.lowercased())"
                } else {
                    requestPrefix = try LabLiveSupport.identifier(
                        requestID,
                        label: "request ID"
                    )
                    guard requestPrefix.utf8.count <= 128 else {
                        throw ValidationError(
                            "request ID must not exceed 128 bytes"
                        )
                    }
                }
                let dataURL = URL(fileURLWithPath: dataDirectory)

                // A recovery CLI must not manufacture an account-local
                // database for an arbitrary DID. Resolve the receiver through
                // control.sqlite and require an authorization-capable account
                // before any OAuth or remote request begins.
                let control: SQLiteControlDatabase
                do {
                    control = try await SQLiteControlDatabase(
                        dataDirectory: dataURL
                    )
                } catch {
                    throw ValidationError(
                        "unable to open Swan control database"
                    )
                }
                do {
                    guard let receiver = try await control.account(
                        did: canonicalReceiver
                    ) else {
                        throw ValidationError(
                            "receiver account is not managed by this Swan data directory"
                        )
                    }
                    guard receiver.status.authorizesAccount else {
                        throw ValidationError("receiver account is not active")
                    }
                    try await control.close()
                } catch {
                    try? await control.close()
                    throw error
                }

                let sourceMember = try await LabLiveSupport.host(
                    label: "member",
                    url: sourceEndpoint,
                    auth: normalizedSourceAuth,
                    tokenFile: sourceTokenFile,
                    handleEnvironment: sourceHandleEnvironment,
                    passwordFile: sourcePasswordFile,
                    clientID: sourceClientID,
                    redirectURI: sourceRedirectURI,
                    scopes: scope,
                    timeout: requestTimeoutSeconds,
                    permissionedCommitVerificationKey: verificationKey
                )
                let authority = try await LabLiveSupport.host(
                    label: "authority",
                    url: authorityEndpoint,
                    auth: "none",
                    tokenFile: nil,
                    handleEnvironment: "SWAN_UNUSED",
                    passwordFile: nil,
                    clientID: "",
                    redirectURI: "",
                    scopes: scope,
                    timeout: requestTimeoutSeconds,
                    permissionedCommitVerificationKey: nil
                )
                let broker = SpaceCredentialBroker(
                    member: sourceMember.client,
                    authority: authority.client
                )

                let database = try await SQLiteAccountDatabase(
                    dataDirectory: dataURL,
                    did: canonicalReceiver,
                    openMode: .existingManaged
                )
                // The remote STAR is staged and verified before this closure is
                // invoked. It opens the control plane only for the final,
                // network-free publication transaction, so deactivation
                // cannot race the authorization decision used by recovery.
                let publicationAuthorization:
                    PermissionedRemoteReplicaRecoveryOrchestrator
                    .PublicationAuthorization = { operation in
                        let publicationControl = try await SQLiteControlDatabase(
                            dataDirectory: dataURL
                        )
                        do {
                            let result = try await publicationControl
                                .withActiveAccountAuthorization(
                                    did: canonicalReceiver,
                                    operation: operation
                                )
                            try await publicationControl.close()
                            return result
                        } catch {
                            try? await publicationControl.close()
                            throw error
                        }
                    }
                let temporaryDirectory = FileManager.default
                    .temporaryDirectory.appending(
                        path: "swan-permissioned-recovery-\(UUID().uuidString)",
                        directoryHint: .isDirectory
                    )
                do {
                    try FileManager.default.createDirectory(
                        at: temporaryDirectory,
                        withIntermediateDirectories: false,
                        attributes: [.posixPermissions: 0o700]
                    )
                } catch {
                    try? await database.close()
                    throw ValidationError(
                        "permissioned recovery staging is unavailable"
                    )
                }

                let limits = SpaceCARRecoveryLimits.standard
                let admission = try PublicRepositorySpoolAdmission(
                    maximumGlobalBytes: limits.maximumCARBytes,
                    maximumPerAccountBytes: limits.maximumCARBytes
                )
                let target = try PermissionedRemoteReplicaTarget(
                    receiverDID: canonicalReceiver,
                    space: parsedSpace,
                    repositoryDID: canonicalRepository
                )
                var gapStatus: Int?
                var gapErrorCode: String?
                var gapFallbackUsed = false
                var priorHead: PermissionedRemoteReplicaHead?
                var valid: CommittedPermissionedRemoteReplicaRecovery?
                var replacementCASAdvanced = false
                var corruptErrorCode: String?
                var finalHead: PermissionedRemoteReplicaHead?
                var corruptionRejected = false
                var preserved = false
                var outcomeError: String?

                do {
                    let credential = try await broker.exchange(
                        space: parsedSpace,
                        memberAuthorization: sourceMember.authorization,
                        memberAuthorizationProvider:
                            sourceMember.authorizationProvider
                    )
                    let source = LiveInteropHost(
                        label: "source",
                        client: sourceMember.client,
                        authorization: .spaceCredential(credential),
                        permissionedCommitVerificationKey: verificationKey,
                        permissionedKEMKeyProvider: try LabLiveSupport.kemKeyProvider()
                    )
                    let gap = try await PermissionedSpaceMACHTTP.query(
                        host: source, nsid: "com.atproto.space.listRepoOps",
                        query: [
                            "space": parsedSpace.rawValue,
                            "repo": canonicalRepository,
                            "since": sinceRevision.toString(),
                            "limit": "1",
                        ],
                        space: parsedSpace, author: canonicalRepository,
                        authorization: { source.authorization },
                        commit: { try StrictJSON.decode(ComAtprotoSpaceListRepoOps.Output.self, from: $0).commit }
                    ).response
                    gapStatus = gap.status
                    gapErrorCode = Self.responseError(gap)
                    let explicitRetentionGap = gap.status == 409
                        && gapErrorCode == "full_repo_recovery_required"
                    let successfulWithoutGapError = (200 ... 299).contains(
                        gap.status
                    ) && gapErrorCode == nil
                    guard explicitRetentionGap
                        || (allowFullCARFallback && successfulWithoutGapError)
                    else {
                        throw PermissionedRecoveryCommandError
                            .retentionGapMissing
                    }
                    gapFallbackUsed = !explicitRetentionGap

                    priorHead = try await database
                        .permissionedRemoteReplicaHead(target: target)
                    if requirePriorHead, priorHead == nil {
                        throw PermissionedRecoveryCommandError.priorHeadRequired
                    }
                    let now = Int64(Date().timeIntervalSince1970)
                    valid = try await LiveInteropRunner
                        .recoverPermissionedRepository(
                            target: target,
                            requestID: "\(requestPrefix)-valid",
                            sourceHost: source,
                            receiverDatabase: database,
                            expiresAt: now + 300,
                            temporaryDirectory: temporaryDirectory,
                            spoolAdmission: admission,
                            limits: limits,
                            publicationAuthorization:
                                publicationAuthorization,
                            now: { Int64(Date().timeIntervalSince1970) }
                        )
                    if let priorHead, let valid {
                        replacementCASAdvanced = valid.head.generation
                            == priorHead.generation + 1
                            && valid.head.wireRevision != priorHead.wireRevision
                            && valid.head.commitment != priorHead.commitment
                    }

                    do {
                        _ = try await LiveInteropRunner
                            .recoverPermissionedRepository(
                                target: target,
                                requestID: "\(requestPrefix)-corrupt",
                                sourceHost: source,
                                receiverDatabase: database,
                                expiresAt: Int64(
                                    Date().timeIntervalSince1970
                                ) + 300,
                                temporaryDirectory: temporaryDirectory,
                                spoolAdmission: admission,
                                limits: limits,
                                sourceFault: .corruptLastByte,
                                publicationAuthorization:
                                    publicationAuthorization,
                                now: {
                                    Int64(Date().timeIntervalSince1970)
                                }
                            )
                    } catch {
                        corruptErrorCode = PermissionedRecoveryFailureCode
                            .code(for: error)
                        // A transport, OAuth, timeout, or unrelated storage
                        // failure is not evidence that the corrupted archive
                        // reached and was rejected by the STAR verifier. The
                        // final-byte mutation removes STAR's archive terminator
                        // and is classified as a truncation.
                        corruptionRejected = PermissionedRecoveryFailureCode
                            .isInjectedFinalByteCorruptionRejection(error)
                    }
                    finalHead = try await database
                        .permissionedRemoteReplicaHead(target: target)
                    preserved = valid?.head == finalHead
                    guard corruptionRejected, preserved,
                          !requirePriorHead || replacementCASAdvanced else {
                        throw PermissionedRecoveryCommandError
                            .corruptRecoveryAccepted
                    }
                } catch {
                    outcomeError = Self.errorCode(for: error)
                }

                let passed = outcomeError == nil
                    && ((gapStatus == 409
                        && gapErrorCode == "full_repo_recovery_required")
                        || (allowFullCARFallback && gapFallbackUsed))
                    && valid != nil
                    && corruptionRejected
                    && preserved
                    && (!requirePriorHead || replacementCASAdvanced)
                let artifact = PermissionedRecoveryAcceptanceArtifact(
                    scenario: scenario,
                    gapStatus: gapStatus,
                    gapErrorCode: gapErrorCode,
                    gapFallbackUsed: gapFallbackUsed,
                    priorHeadGeneration: priorHead?.generation,
                    priorHeadRevision: priorHead?.wireRevision.toString(),
                    priorCommitment: priorHead.map {
                        Hex.encode($0.commitment)
                    },
                    replacementHeadGeneration: valid?.head.generation,
                    replacementHeadRevision: valid?.head.wireRevision.toString(),
                    replacementCommitment: valid.map {
                        Hex.encode($0.head.commitment)
                    },
                    replacementRecordCount: valid?.recordCount,
                    replacementCASAdvanced: replacementCASAdvanced,
                    corruptionRejected: corruptionRejected,
                    corruptErrorCode: corruptErrorCode,
                    finalHeadGeneration: finalHead?.generation,
                    finalHeadRevision: finalHead?.wireRevision.toString(),
                    finalCommitment: finalHead.map {
                        Hex.encode($0.commitment)
                    },
                    lastValidHeadPreserved: preserved,
                    status: passed ? "passed" : "failed",
                    errorCode: outcomeError
                )
                let outputURL = URL(fileURLWithPath: output)
                do {
                    try FileManager.default.createDirectory(
                        at: outputURL.deletingLastPathComponent(),
                        withIntermediateDirectories: true
                    )
                    let encoder = JSONEncoder()
                    encoder.outputFormatting = [
                        .sortedKeys, .withoutEscapingSlashes,
                    ]
                    try encoder.encode(artifact).write(
                        to: outputURL,
                        options: .atomic
                    )
                    try FileManager.default.setAttributes(
                        [.posixPermissions: 0o600],
                        ofItemAtPath: outputURL.path
                    )
                } catch {
                    try? await database.close()
                    try? FileManager.default.removeItem(
                        at: temporaryDirectory
                    )
                    throw ValidationError(
                        "unable to write sanitized recovery artifact"
                    )
                }
                try? FileManager.default.removeItem(at: temporaryDirectory)
                do {
                    try await database.close()
                } catch {
                    throw ValidationError(
                        "unable to close receiver database"
                    )
                }
                print(
                    "PERMISSIONED RECOVERY ARTIFACT WRITTEN: \(outputURL.path) status=\(artifact.status)"
                )
                guard !failOnFailure || passed else {
                    throw ValidationError(
                        "permissioned recovery acceptance did not pass; inspect \(outputURL.lastPathComponent)"
                    )
                }
            }

            private enum PermissionedRecoveryCommandError: Error {
                case retentionGapMissing
                case priorHeadRequired
                case corruptRecoveryAccepted
            }

            private struct ErrorBody: Decodable {
                let error: String
            }

            private static func responseError(
                _ response: InteropHTTPResponse
            ) -> String? {
                (try? StrictJSON.decode(
                    ErrorBody.self,
                    from: response.body
                ))?.error
            }

            private static func errorCode(for error: Error) -> String {
                if let command = error as? PermissionedRecoveryCommandError {
                    switch command {
                    case .retentionGapMissing:
                        return "RetentionGapMissing"
                    case .priorHeadRequired:
                        return "PriorHeadRequired"
                    case .corruptRecoveryAccepted:
                        return "RecoveryRejected"
                    }
                }
                return PermissionedRecoveryFailureCode.code(for: error)
            }
        }

        struct Validate: ParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Check the pinned reference archive and extracted source cache without starting Compose"
            )

            @Option(name: .long, help: "Swan package root containing .interop-cache")
            var root: String = "."

            func run() throws {
                let rootURL = URL(fileURLWithPath: root)
                let report = InteropLaboratory.validate(
                    cacheDirectory: rootURL.appending(path: ".interop-cache", directoryHint: .isDirectory)
                )
                guard report.isValid else {
                    for diagnostic in report.diagnostics {
                        FileHandle.standardError.write(Data("lab prerequisite failed: \(diagnostic.rawValue)\n".utf8))
                    }
                    throw ValidationError(
                        "pinned reference cache is not ready; run interop/fetch-reference.sh and retry"
                    )
                }
                let pin = ReferenceSourcePin()
                print("LAB PREREQUISITES OK: \(pin.commit)")
            }
        }

        struct Scenario: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Probe host endpoints and record sanitized interoperability scenario output"
            )

            @Option(name: .long, help: "Scenario identifier (letters, numbers, hyphen, and underscore only)")
            var name: String = "reference-matrix"

            @Option(
                name: .long,
                parsing: .upToNextOption,
                help: "Repeatable fault mode: offline, disconnected, delayed, duplicated, reordered, or corrupted"
            )
            var fault: [String] = []

            @Option(name: .long, help: "Explicit destination for the sanitized JSON artifact")
            var output: String

            @Option(name: .long, help: "Swan base URL for scenario probes (default: https://swan.test)")
            var swanBaseURL: String = ""

            @Option(name: .long, help: "Reference PDS base URL for scenario probes (default: https://pds.test)")
            var referenceBaseURL: String = ""

            @Option(name: .long, help: "Per-request timeout in seconds for scenario probes")
            var requestTimeoutSeconds: Double = 8

            @Flag(name: .long, help: "Require strict cross-host convergence for every probed endpoint")
            var strictConvergence: Bool = false

            @Option(
                name: .long,
                parsing: .upToNextOption,
                help: "Repeatable allowlist for strict-convergence mismatches (path or METHOD path)")
            var allowedConvergenceDivergences: [String] = []

            @Flag(
                name: .customLong("fail-on-failure"),
                inversion: .prefixedNo,
                help: "Return non-zero when scenario status is not passed (default; use --no-fail-on-failure only for diagnostics)"
            )
            var failOnFailure: Bool = true

            func run() async throws {
                let normalizedScenario = name.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !normalizedScenario.isEmpty,
                      normalizedScenario.unicodeScalars.allSatisfy({
                          CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_")).contains($0)
                      }) else {
                    throw ValidationError("scenario must be an alphanumeric identifier using only letters, numbers, '-' and '_'")
                }
                let modes = try fault.map { rawValue -> FaultMode in
                    guard let mode = FaultMode(rawValue: rawValue) else {
                        throw ValidationError("unsupported lab fault mode")
                    }
                    return mode
                }

                let swanURLString = !swanBaseURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    ? swanBaseURL
                    : ProcessInfo.processInfo.environment["SWAN_SCENARIO_SWAN_URL"] ?? "https://swan.test"
                let referenceURLString = !referenceBaseURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    ? referenceBaseURL
                    : ProcessInfo.processInfo.environment["SWAN_SCENARIO_REFERENCE_URL"] ?? "https://pds.test"

                guard let swanURL = URL(string: swanURLString), let referenceURL = URL(string: referenceURLString) else {
                    throw ValidationError("lab scenario URL is invalid")
                }

                let runtimeConfiguration = InteropScenarioRunner.RuntimeConfiguration(
                    swanBaseURL: swanURL,
                    referenceBaseURL: referenceURL,
                    timeoutInterval: requestTimeoutSeconds,
                    strictConvergence: strictConvergence,
                    allowedConvergenceDivergences: Set(allowedConvergenceDivergences.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() })
                )

                let artifact = await InteropScenarioRunner.execute(
                    scenario: normalizedScenario,
                    faultModes: modes,
                    runtime: runtimeConfiguration
                )
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                let outputURL = URL(fileURLWithPath: output)
                try FileManager.default.createDirectory(
                    at: outputURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                try encoder.encode(artifact).write(to: outputURL, options: .atomic)
                print("INTEROP SCENARIO ARTIFACT WRITTEN")
                guard !failOnFailure || artifact.status == "passed" else {
                    throw ValidationError("interop scenario did not pass; inspect \(outputURL.lastPathComponent)")
                }
            }
        }

        struct Semantic: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Run the offline durable Swan-to-Swan semantic interoperability checks"
            )

            @Option(name: .long, help: "Scenario identifier (letters, numbers, hyphen, and underscore only)")
            var name: String = "swan-swan-semantic"

            @Option(name: .long, help: "Destination for the sanitized semantic JSON artifact")
            var output: String = "artifacts/swan-swan-semantic.json"

            @Flag(
                name: .customLong("fail-on-failure"),
                inversion: .prefixedNo,
                help: "Return non-zero when the semantic artifact is not passed (default; use --no-fail-on-failure only for diagnostics)"
            )
            var failOnFailure: Bool = true

            func run() async throws {
                let normalizedScenario = name.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !normalizedScenario.isEmpty,
                      normalizedScenario.unicodeScalars.allSatisfy({
                          CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_")).contains($0)
                      }) else {
                    throw ValidationError("semantic scenario must be an alphanumeric identifier using only letters, numbers, '-' and '_'")
                }

                let artifact = await LocalSemanticInteropRunner.execute(
                    scenario: normalizedScenario
                )
                let outputURL = URL(fileURLWithPath: output)
                try FileManager.default.createDirectory(
                    at: outputURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                try encoder.encode(artifact).write(to: outputURL, options: .atomic)
                print("LOCAL SEMANTIC ARTIFACT WRITTEN: \(outputURL.path) status=\(artifact.status)")
                guard !failOnFailure || artifact.status == "passed" else {
                    throw ValidationError("local semantic interoperability did not pass; inspect \(outputURL.lastPathComponent)")
                }
            }
        }

        struct StatefulFaultMatrix: ParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "stateful-fault-matrix",
                abstract: "Validate durable cross-host fault witnesses and write a sanitized matrix artifact"
            )

            @Option(name: .long, help: "Bounded JSON witness input produced by the live harness")
            var input: String

            @Option(name: .long, help: "Destination for the sanitized matrix artifact")
            var output: String = "artifacts/live/stateful-fault-matrix.json"

            @Flag(
                name: .customLong("fail-on-failure"),
                inversion: .prefixedNo
            )
            var failOnFailure = true

            func run() throws {
                let inputURL = URL(fileURLWithPath: input).standardizedFileURL
                let raw = try readBoundedRegularFileNoFollow(
                    inputURL,
                    maximumBytes: 1024 * 1024,
                    validationMessage:
                        "stateful fault witness input must be a regular file no larger than 1 MiB"
                )
                let document: InputDocument
                do {
                    document = try StrictJSON.decode(InputDocument.self, from: raw)
                } catch {
                    throw ValidationError("stateful fault witness input is invalid")
                }
                let cells = try document.cells.map { try $0.validated() }
                let artifact = StatefulFaultInteropMatrixArtifact(
                    scenario: document.scenario,
                    cells: cells
                )
                let outputURL = URL(fileURLWithPath: output).standardizedFileURL
                try FileManager.default.createDirectory(
                    at: outputURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                try encoder.encode(artifact).write(to: outputURL, options: .atomic)
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: outputURL.path
                )
                print("STATEFUL FAULT MATRIX ARTIFACT WRITTEN: \(outputURL.path) status=\(artifact.status)")
                guard !failOnFailure || artifact.status == "passed" else {
                    throw ValidationError("stateful fault matrix did not pass; inspect \(outputURL.lastPathComponent)")
                }
            }

            private struct InputDocument: Decodable {
                let scenario: String
                let cells: [InputCell]
            }

            private struct InputCell: Decodable {
                let mode: StatefulFaultMode
                let before: InputHead?
                let intended: InputHead
                let afterFault: InputHead?
                let afterHeal: InputHead?
                let faultObserved: Bool
                let invalidDeliveryRejected: Bool

                func validated() throws -> StatefulFaultInteropCell {
                    guard let intended = intended.validated() else {
                        throw ValidationError("stateful fault witness head is invalid")
                    }
                    let before = try validatedOptional(self.before)
                    let afterFault = try validatedOptional(self.afterFault)
                    let afterHeal = try validatedOptional(self.afterHeal)
                    return StatefulFaultInteropCell(
                        mode: mode,
                        before: before,
                        intended: intended,
                        afterFault: afterFault,
                        afterHeal: afterHeal,
                        faultObserved: faultObserved,
                        invalidDeliveryRejected: invalidDeliveryRejected
                    )
                }

                private func validatedOptional(
                    _ value: InputHead?
                ) throws -> StatefulReplicaHeadWitness? {
                    guard let value else { return nil }
                    guard let head = value.validated() else {
                        throw ValidationError("stateful fault witness head is invalid")
                    }
                    return head
                }
            }

            private struct InputHead: Decodable {
                let generation: UInt64
                let revision: String
                let commitment: String

                func validated() -> StatefulReplicaHeadWitness? {
                    StatefulReplicaHeadWitness(
                        generation: generation,
                        revision: revision,
                        commitment: commitment
                    )
                }
            }
        }

        struct PermissionedReplicaHead: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "permissioned-replica-head",
                abstract: "Write a secret-free witness of one durable permissioned replica head"
            )

            @Option(name: .customLong("receiver-did"))
            var receiverDID: String
            @Option(name: .long)
            var repository: String
            @Option(name: .long)
            var space: String
            @Option(name: .long)
            var dataDirectory: String
            @Option(name: .long)
            var output: String

            func run() async throws {
                let receiver: String
                let repository: String
                let space: SpaceURI
                do {
                    receiver = try AccountIdentifiers.validateDID(receiverDID)
                    repository = try AccountIdentifiers.validateDID(self.repository)
                    space = try SpaceURI(self.space)
                } catch {
                    throw ValidationError("permissioned replica selector is invalid")
                }
                let dataURL = URL(fileURLWithPath: dataDirectory)
                let control = try await SQLiteControlDatabase(
                    dataDirectory: dataURL
                )
                do {
                    guard let account = try await control.account(did: receiver),
                          account.status.authorizesAccount else {
                        throw ValidationError("receiver account is not active")
                    }
                    try await control.close()
                } catch {
                    try? await control.close()
                    throw error
                }
                let database = try await SQLiteAccountDatabase(
                    dataDirectory: dataURL,
                    did: receiver,
                    openMode: .existingManaged
                )
                let target = try PermissionedRemoteReplicaTarget(
                    receiverDID: receiver,
                    space: space,
                    repositoryDID: repository
                )
                let head = try await database.permissionedRemoteReplicaHead(
                    target: target
                )
                try await database.close()
                let witness: StatefulReplicaHeadWitness?
                if let head {
                    witness = StatefulReplicaHeadWitness(
                        generation: head.generation,
                        revision: head.wireRevision.toString(),
                        commitment: Hex.encode(head.commitment)
                    )
                    guard witness != nil else {
                        throw ValidationError("durable replica head is invalid")
                    }
                } else {
                    witness = nil
                }
                let outputURL = URL(fileURLWithPath: output).standardizedFileURL
                try FileManager.default.createDirectory(
                    at: outputURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                try encoder.encode(Artifact(head: witness)).write(
                    to: outputURL,
                    options: .atomic
                )
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: outputURL.path
                )
                print("PERMISSIONED REPLICA HEAD WRITTEN: \(outputURL.path)")
            }

            private struct Artifact: Encodable {
                let profileID = OfflineProtocolProfileVerifier.stableProfileID
                let head: StatefulReplicaHeadWitness?
            }
        }

        struct ImportPublic: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "import-public",
                abstract: "Stream and durably import a public sync.getRepo CAR"
            )

            @Option(name: .long, help: "Reference or remote PDS base URL (default: https://pds.test)")
            var remoteURL: String = ""

            @Option(name: .long, help: "Swan data directory containing the target account database")
            var dataDirectory: String

            @Option(name: .long, help: "Repository DID to fetch and install")
            var did: String

            @Option(name: .customLong("commit-key-env"), help: "Environment variable containing the repository public key as canonical base64url")
            var commitKeyEnvironment: String = "SWAN_LAB_PUBLIC_REPO_KEY"

            @Option(name: .customLong("commit-key-algorithm"), help: "Repository signature algorithm: p256 or secp256k1")
            var commitKeyAlgorithm: String = "p256"

            @Flag(
                name: .customLong("resolve-commit-key"),
                help: "Resolve the repository's atproto verification key from PLC instead of reading --commit-key-env"
            )
            var resolveCommitKey = false

            @Option(
                name: .customLong("plc-origin"),
                help: "PLC directory origin used with --resolve-commit-key (default: https://plc.directory)"
            )
            var plcOrigin: String = PLCClientConfiguration.defaultProductionOrigin.absoluteString

            @Flag(
                name: .customLong("plc-laboratory"),
                help: "Allow an explicitly loopback/allowlisted HTTP PLC origin for the lab"
            )
            var plcLaboratory = false

            @Option(
                name: .customLong("plc-laboratory-allowlisted-host"),
                help: "Explicit Docker/service DNS host allowed for --plc-laboratory"
            )
            var plcLaboratoryAllowlistedHost: String?

            @Option(name: .long, help: "Idempotency request identifier; defaults to the current base commit")
            var requestID: String = ""

            @Flag(
                name: .customLong("promote-public-blobs"),
                help: "Fetch raw-CID blobs from the remote PDS and adopt them in the receiver's public namespace after CAR import"
            )
            var promotePublicBlobs = false

            @Option(name: .long, help: "Destination for the sanitized import artifact")
            var output: String = "artifacts/public-repository-import.json"

            @Option(name: .long, help: "Per-request timeout in seconds")
            var requestTimeoutSeconds: Double = 15

            @Flag(
                name: .customLong("fail-on-failure"),
                inversion: .prefixedNo,
                help: "Return non-zero when the import does not commit (default)"
            )
            var failOnFailure: Bool = true

            func run() async throws {
                let canonicalDID: String
                do {
                    canonicalDID = try AccountIdentifiers.validateDID(did)
                } catch {
                    throw ValidationError("--did is not a canonical DID")
                }
                guard !dataDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    throw ValidationError("--data-directory is required")
                }
                let normalizedAlgorithm = commitKeyAlgorithm
                    .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                guard normalizedAlgorithm == "p256" || normalizedAlgorithm == "secp256k1" else {
                    throw ValidationError("--commit-key-algorithm must be p256 or secp256k1")
                }
                if !resolveCommitKey {
                    guard !plcLaboratory,
                          plcLaboratoryAllowlistedHost == nil,
                          plcOrigin == PLCClientConfiguration.defaultProductionOrigin.absoluteString else {
                        throw ValidationError(
                            "--plc-origin and laboratory PLC options require --resolve-commit-key"
                        )
                    }
                }
                let baseURL = try LabLiveSupport.url(
                    explicit: remoteURL,
                    environment: "SWAN_LAB_PUBLIC_REPOSITORY_URL",
                    fallback: "https://pds.test"
                )
                guard requestTimeoutSeconds > 0,
                      requestTimeoutSeconds <= 120,
                      requestTimeoutSeconds.isFinite else {
                    throw ValidationError("--request-timeout-seconds is invalid")
                }
                let keyResolver: (any PublicRepositoryCommitKeyResolving)?
                if resolveCommitKey {
                    guard let origin = URL(string: plcOrigin) else {
                        throw ValidationError("--plc-origin must be a URL")
                    }
                    let configuration: PLCClientConfiguration
                    do {
                        if plcLaboratory {
                            configuration = try .laboratory(
                                origin: origin,
                                allowlistedHost: plcLaboratoryAllowlistedHost
                            )
                        } else {
                            guard plcLaboratoryAllowlistedHost == nil else {
                                throw ValidationError(
                                    "--plc-laboratory-allowlisted-host requires --plc-laboratory"
                                )
                            }
                            configuration = try .production(origin: origin)
                        }
                        keyResolver = try PLCPublicRepositoryCommitKeyResolver(
                            configuration: configuration
                        )
                    } catch let error as ValidationError {
                        throw error
                    } catch {
                        throw ValidationError("--plc-origin is not an allowed PLC origin")
                    }
                } else {
                    keyResolver = nil
                }

                let database = try await SQLiteAccountDatabase(
                    dataDirectory: URL(fileURLWithPath: dataDirectory),
                    did: canonicalDID
                )
                defer { Task { try? await database.close() } }
                guard let current = try await database.loadPublicRepositoryState() else {
                    throw ValidationError("target account public repository is unavailable")
                }
                let id = requestID.isEmpty
                    ? "sync-\(current.commitCID.string)"
                    : requestID
                // A public CAR import keeps its network spool while SQLite
                // adopts blocks; blob promotion keeps that response while a
                // second bounded adoption spool is active. Reserve enough
                // process/account budget for that deliberate two-spool case.
                let importSpoolAdmission = try PublicRepositorySpoolAdmission(
                    maximumGlobalBytes: 2 * 1_024 * 1_024 * 1_024,
                    maximumPerAccountBytes: 1 * 1_024 * 1_024 * 1_024
                )
                let importer = RemotePublicRepositoryCARImporter(
                    client: try InteropXRPCClient(baseURL: baseURL, timeout: requestTimeoutSeconds),
                    spoolAdmission: importSpoolAdmission
                )
                let blobPromoter = RemotePublicRepositoryBlobPromoter(
                    client: importer.client,
                    spoolAdmission: importSpoolAdmission
                )
                let result: PublicRepositoryCARImportArtifact
                do {
                    let imported: CommittedPublicRepositoryImport
                    if let keyResolver {
                        imported = try await importer.importRepository(
                            did: canonicalDID,
                            database: database,
                            keyResolver: keyResolver,
                            requestID: id
                        )
                    } else {
                        let encodedKey = try LabLiveSupport.environmentValue(
                            commitKeyEnvironment,
                            label: "public repository commit key"
                        )
                        guard let keyBytes = Data(base64URLEncoded: encodedKey),
                              keyBytes.base64URLEncodedString() == encodedKey else {
                            throw ValidationError("public repository commit key is not canonical base64url")
                        }
                        let verificationKey: PermissionedDataJWTVerificationKey
                        do {
                            switch normalizedAlgorithm {
                            case "p256":
                                verificationKey = .p256(
                                    try P256.Signing.PublicKey(x963Representation: keyBytes)
                                )
                            default:
                                verificationKey = try PermissionedDataJWTVerificationKey(
                                    secp256k1PublicKey: keyBytes
                                )
                            }
                        } catch {
                            throw ValidationError("public repository commit key is invalid")
                        }
                        imported = try await importer.importRepository(
                            did: canonicalDID,
                            database: database,
                            verifier: PermissionedDataPublicRepositoryCommitVerifier(key: verificationKey),
                            requestID: id
                        )
                    }
                    let promotedBlobCount: Int?
                    if promotePublicBlobs {
                        promotedBlobCount = try await blobPromoter
                            .promoteReferencedBlobs(in: database, did: canonicalDID)
                            .promotedBlobCount
                    } else {
                        promotedBlobCount = nil
                    }
                    result = PublicRepositoryCARImportArtifact(
                        remoteHost: baseURL.host ?? "remote",
                        repositoryDID: canonicalDID,
                        httpStatus: 200,
                        baseCommitCID: current.commitCID.string,
                        importedCommitCID: imported.state.commitCID.string,
                        importedDataCID: imported.state.dataCID.string,
                        importedRevision: imported.state.revision,
                        reachableBlockCount: imported.reachableBlockCount,
                        recordCount: imported.recordCount,
                        promotedBlobCount: promotedBlobCount,
                        status: "passed",
                        errorCode: nil
                    )
                } catch {
                    result = PublicRepositoryCARImportArtifact(
                        remoteHost: baseURL.host ?? "remote",
                        repositoryDID: canonicalDID,
                        httpStatus: nil,
                        baseCommitCID: current.commitCID.string,
                        importedCommitCID: nil,
                        importedDataCID: nil,
                        importedRevision: nil,
                        reachableBlockCount: nil,
                        recordCount: nil,
                        promotedBlobCount: nil,
                        status: "failed",
                        errorCode: PublicRepositoryCARImportFailureCode.code(for: error)
                    )
                }
                let outputURL = URL(fileURLWithPath: output)
                try FileManager.default.createDirectory(
                    at: outputURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                try encoder.encode(result).write(to: outputURL, options: .atomic)
                print("PUBLIC REPOSITORY IMPORT ARTIFACT WRITTEN: \(outputURL.path) status=\(result.status)")
                guard !failOnFailure || result.status == "passed" else {
                    throw ValidationError("public repository import did not pass; inspect \(outputURL.lastPathComponent)")
                }
            }
        }

        struct Live: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Run one stateful public or permissioned cross-host round trip"
            )

            @Option(name: .long, help: "Round-trip mode: public or permissioned")
            var mode: String = "public"

            @Option(name: .long, help: "Scenario identifier (letters, numbers, hyphen, and underscore only)")
            var name: String = "live-round-trip"

            @Option(name: .long, help: "Producer URL, or member URL in permissioned mode")
            var producerURL: String = ""

            @Option(name: .long, help: "Consumer URL, or authority URL in permissioned mode")
            var consumerURL: String = ""

            @Option(name: .long, help: "Producer/member auth: none, bearer, or oauth")
            var producerAuth: String = "none"

            @Option(name: .long, help: "Consumer auth: none or bearer (ignored for permissioned credential reads)")
            var consumerAuth: String = "none"

            @Option(name: .customLong("producer-token-file"), help: "Owner-only file containing producer/member bearer token")
            var producerTokenFile: String?

            @Option(name: .customLong("consumer-token-file"), help: "Owner-only file containing consumer bearer token")
            var consumerTokenFile: String?

            @Option(name: .customLong("producer-handle-env"), help: "Producer/member OAuth handle environment variable")
            var producerHandleEnv: String = "SWAN_LAB_PRODUCER_HANDLE"

            @Option(name: .customLong("producer-password-file"), help: "Owner-only file containing producer/member OAuth password")
            var producerPasswordFile: String?

            @Option(name: .customLong("consumer-handle-env"), help: "Consumer OAuth handle environment variable")
            var consumerHandleEnv: String = "SWAN_LAB_CONSUMER_HANDLE"

            @Option(name: .customLong("consumer-password-file"), help: "Owner-only file containing consumer OAuth password")
            var consumerPasswordFile: String?
            @Option(name: .long, help: "Producer/member OAuth client metadata URL")
            var producerClientID: String = ""

            @Option(name: .long, help: "Producer/member OAuth redirect URI")
            var producerRedirectURI: String = ""

            @Option(name: .long, help: "Consumer OAuth client metadata URL")
            var consumerClientID: String = ""

            @Option(name: .long, help: "Consumer OAuth redirect URI")
            var consumerRedirectURI: String = ""

            @Option(name: .long, parsing: .upToNextOption, help: "OAuth scope to request; repeatable")
            var scope: [String] = ["atproto"]

            @Option(name: .long, help: "Public repository DID; required in public mode")
            var repository: String = ""

            @Option(name: .long, help: "Public record collection NSID; required in public mode")
            var collection: String = ""

            @Option(name: .long, help: "Public record key; required in public mode")
            var rkey: String = ""

            @Option(name: .long, help: "Permissioned space URI; required in permissioned mode")
            var space: String = ""

            @Option(
                name: .customLong("permissioned-read-host"),
                help: "Permissioned repository host for the credential read: authority (default) or member"
            )
            var permissionedReadHost: String = "authority"

            @Flag(
                name: .customLong("provision-space"),
                help: "Create the permissioned space and add the read-query repository DID before the round trip"
            )
            var provisionSpace = false

            @Flag(
                name: .customLong("permissioned-list-ops"),
                help: "Fetch and cryptographically verify the repository host's terminal space.listRepoOps page"
            )
            var permissionedListOps = false

            @Flag(
                name: .customLong("permissioned-list-ops-exclude-values"),
                help: "Request the metadata-only listRepoOps form"
            )
            var permissionedListOpsExcludeValues = false

            @Flag(
                name: .customLong("permissioned-get-repo"),
                help: "Fetch and verify the repository host's full STAR snapshot and response MAC"
            )
            var permissionedGetRepo = false

            @Flag(
                name: .customLong("permissioned-stateful-matrix"),
                help: "Require create/read CID convergence plus verified listRepoOps revision/commitment and full-STAR recovery evidence"
            )
            var permissionedStatefulMatrix = false

            @Flag(
                name: .customLong("permissioned-write-only-apply-writes"),
                help: "Opt in to one member OAuth/DPoP applyWrites batch plus a metadata-only MAC-authenticated terminal-revision witness"
            )
            var permissionedWriteOnlyApplyWrites = false

            @Option(
                name: .customLong("permissioned-commit-key-env"),
                help: "Compatibility option only; native reads use SWAN_LAB_KEM_KEYS_FILE or SWAN_LAB_KEM_PUBLIC_KEY"
            )
            var permissionedCommitKeyEnvironment = "SWAN_LAB_PERMISSIONED_COMMIT_KEY"

            @Option(name: .long, help: "JSON request body file for the write")
            var bodyFile: String

            @Option(name: .customLong("blob-file"), help: "Optional blob body file to upload before the record write (public or permissioned)")
            var blobFile: String?

            @Option(name: .long, parsing: .upToNextOption, help: "Permissioned read query item key=value; repeatable")
            var readQuery: [String] = []

            @Option(name: .long, help: "Destination for the sanitized JSON artifact")
            var output: String = "artifacts/live-round-trip.json"

            @Option(name: .long, help: "Per-request timeout in seconds")
            var requestTimeoutSeconds: Double = 15

            @Flag(
                name: .customLong("fail-on-failure"),
                inversion: .prefixedNo,
                help: "Return non-zero when the semantic artifact is not passed (default)"
            )
            var failOnFailure: Bool = true

            func run() async throws {
                let normalizedMode = mode.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                guard normalizedMode == "public" || normalizedMode == "permissioned" else {
                    throw ValidationError("live mode must be public or permissioned")
                }
                guard !(normalizedMode == "permissioned"
                    && permissionedStatefulMatrix
                    && permissionedListOpsExcludeValues) else {
                    throw ValidationError(
                        "--permissioned-stateful-matrix requires value-bearing listRepoOps; remove --permissioned-list-ops-exclude-values"
                    )
                }
                if permissionedWriteOnlyApplyWrites {
                    guard normalizedMode == "permissioned" else {
                        throw ValidationError(
                            "--permissioned-write-only-apply-writes requires --mode permissioned"
                        )
                    }
                    guard !provisionSpace,
                          !permissionedListOps,
                          !permissionedListOpsExcludeValues,
                          !permissionedGetRepo,
                          !permissionedStatefulMatrix,
                          readQuery.isEmpty,
                          blobFile == nil else {
                        throw ValidationError(
                            "--permissioned-write-only-apply-writes is incompatible with read, provision, listRepoOps, full-CAR, stateful, or blob flags"
                        )
                    }
                    guard !space.isEmpty else {
                        throw ValidationError(
                            "permissioned write-only applyWrites requires --space"
                        )
                    }
                    let parsedSpace: SpaceURI
                    do {
                        parsedSpace = try SpaceURI(space)
                    } catch {
                        throw ValidationError("--space is not a valid space URI")
                    }
                    let canonicalRepository: String
                    do {
                        canonicalRepository = try AccountIdentifiers.validateDID(repository)
                    } catch {
                        throw ValidationError(
                            "permissioned write-only applyWrites requires canonical --repository member DID"
                        )
                    }
                    let normalizedScenario = try LabLiveSupport.identifier(name, label: "scenario")
                    let body = try LabLiveSupport.body(at: URL(fileURLWithPath: bodyFile))
                    guard LiveInteropRunner.pinnedApplyWritesOperationCount(
                        body,
                        space: parsedSpace,
                        repository: canonicalRepository
                    ) != nil else {
                        throw ValidationError(
                            "--permissioned-write-only-apply-writes requires the pinned com.atproto.space.applyWrites create-only body shape"
                        )
                    }
                    let producerURL = try LabLiveSupport.url(
                        explicit: producerURL,
                        environment: "SWAN_LAB_PRODUCER_URL",
                        fallback: "https://swan.test"
                    )
                    let permissionedCommitKey: PermissionedDataJWTVerificationKey? = nil
                    let producer = try await LabLiveSupport.host(
                        label: "member",
                        url: producerURL,
                        auth: producerAuth,
                        tokenFile: producerTokenFile,
                        handleEnvironment: producerHandleEnv,
                        passwordFile: producerPasswordFile,
                        clientID: producerClientID,
                        redirectURI: producerRedirectURI,
                        scopes: scope,
                        timeout: requestTimeoutSeconds,
                        permissionedCommitVerificationKey: permissionedCommitKey
                    )
                    let result = await LiveInteropRunner.permissionedWriteOnlyApplyWrites(
                        scenario: normalizedScenario,
                        member: producer,
                        space: parsedSpace,
                        repository: canonicalRepository,
                        body: body
                    )
                    let outputURL = URL(fileURLWithPath: output)
                    try FileManager.default.createDirectory(
                        at: outputURL.deletingLastPathComponent(),
                        withIntermediateDirectories: true
                    )
                    let encoder = JSONEncoder()
                    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                    try encoder.encode(result).write(to: outputURL, options: .atomic)
                    print("LIVE INTEROP ARTIFACT WRITTEN: \(outputURL.path) status=\(result.status)")
                    guard !failOnFailure || result.status == "passed" else {
                        throw ValidationError(
                            "live interoperability did not pass; inspect \(outputURL.lastPathComponent)"
                        )
                    }
                    return
                }
                let normalizedScenario = try LabLiveSupport.identifier(name, label: "scenario")
                let producerURL = try LabLiveSupport.url(
                    explicit: producerURL,
                    environment: "SWAN_LAB_PRODUCER_URL",
                    fallback: "https://swan.test"
                )
                let consumerURL = try LabLiveSupport.url(
                    explicit: consumerURL,
                    environment: "SWAN_LAB_CONSUMER_URL",
                    fallback: "https://pds.test"
                )
                let permissionedCommitKey: PermissionedDataJWTVerificationKey? = nil
                let producer = try await LabLiveSupport.host(
                    label: normalizedMode == "permissioned" ? "member" : "producer",
                    url: producerURL,
                    auth: producerAuth,
                    tokenFile: producerTokenFile,
                    handleEnvironment: producerHandleEnv,
                    passwordFile: producerPasswordFile,
                    clientID: producerClientID,
                    redirectURI: producerRedirectURI,
                    scopes: scope,
                    timeout: requestTimeoutSeconds,
                    permissionedCommitVerificationKey: permissionedCommitKey
                )
                let consumer = try await LabLiveSupport.host(
                    label: normalizedMode == "permissioned" ? "authority" : "consumer",
                    url: consumerURL,
                    auth: consumerAuth,
                    tokenFile: consumerTokenFile,
                    handleEnvironment: consumerHandleEnv,
                    passwordFile: consumerPasswordFile,
                    clientID: consumerClientID,
                    redirectURI: consumerRedirectURI,
                    scopes: scope,
                    timeout: requestTimeoutSeconds,
                    permissionedCommitVerificationKey: permissionedCommitKey
                )
                let body = try LabLiveSupport.body(at: URL(fileURLWithPath: bodyFile))
                let blobBody = try blobFile.map {
                    try LabLiveSupport.body(at: URL(fileURLWithPath: $0))
                }
                let artifact: any Encodable
                let status: String
                if normalizedMode == "public" {
                    guard !repository.isEmpty, !collection.isEmpty, !rkey.isEmpty else {
                        throw ValidationError("public live mode requires --repository, --collection, and --rkey")
                    }
                    let result = await LiveInteropRunner.publicPutAndRead(
                        scenario: normalizedScenario,
                        producer: producer,
                        consumer: consumer,
                        repository: repository,
                        collection: collection,
                        rkey: rkey,
                        putBody: body,
                        blobBody: blobBody
                    )
                    artifact = result
                    status = result.status
                } else {
                    guard !space.isEmpty else {
                        throw ValidationError("permissioned live mode requires --space")
                    }
                    let parsedSpace: SpaceURI
                    do {
                        parsedSpace = try SpaceURI(space)
                    } catch {
                        throw ValidationError("--space is not a valid space URI")
                    }
                    let query = try LabLiveSupport.query(readQuery)
                    if provisionSpace {
                        guard let memberDID = query["repo"], !memberDID.isEmpty else {
                            throw ValidationError("--provision-space requires --read-query repo=<member DID>")
                        }
                        try await LabLiveSupport.provisionSpace(
                            authority: consumer,
                            space: parsedSpace,
                            member: memberDID
                        )
                    }
                    let broker = SpaceCredentialBroker(
                        member: producer.client,
                        authority: consumer.client
                    )
                    let readHost: LiveInteropHost?
                    switch permissionedReadHost.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
                    case "authority":
                        readHost = consumer
                    case "member":
                        readHost = producer
                    default:
                        throw ValidationError("--permissioned-read-host must be authority or member")
                    }
                    if permissionedStatefulMatrix {
                        let result = await StatefulInteropMatrixRunner.execute(
                            scenario: normalizedScenario,
                            member: producer,
                            authority: consumer,
                            broker: broker,
                            space: parsedSpace,
                            createBody: body,
                            readQuery: query,
                            blobBody: blobBody,
                            readHost: readHost,
                            includeIncrementalValues: !permissionedListOpsExcludeValues
                        )
                        artifact = result
                        status = result.status
                    } else {
                        let result = await LiveInteropRunner.permissionedCreateAndRead(
                            scenario: normalizedScenario,
                            member: producer,
                            authority: consumer,
                            broker: broker,
                            space: parsedSpace,
                            createBody: body,
                            readQuery: query,
                            blobBody: blobBody,
                            readHost: readHost,
                            verifyIncrementalSync: permissionedListOps,
                            includeIncrementalValues: !permissionedListOpsExcludeValues,
                            verifyFullCAR: permissionedGetRepo
                        )
                        artifact = result
                        status = result.status
                    }
                }
                let outputURL = URL(fileURLWithPath: output)
                try FileManager.default.createDirectory(
                    at: outputURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                try encoder.encode(AnyEncodable(artifact)).write(to: outputURL, options: .atomic)
                print("LIVE INTEROP ARTIFACT WRITTEN: \(outputURL.path) status=\(status)")
                guard !failOnFailure || status == "passed" else {
                    throw ValidationError("live interoperability did not pass; inspect \(outputURL.lastPathComponent)")
                }
            }
        }

        struct Forum: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "forum",
                abstract: "Exercise a permissioned-data forum: provision a space, post records, and merge one thread",
                subcommands: [Provision.self, Post.self, Thread.self]
            )

            static let postCollection = "blue.catbird.lab.post"
            static let replyCollection = "blue.catbird.lab.reply"

            /// Creates a forum space on an authority and adds one member.
            /// Mirrors `lab live --provision-space`: it reuses
            /// `LabLiveSupport.provisionSpace` (space.createSpace +
            /// putMembers) through the OAuth-authorized procedure helper.
            struct Provision: AsyncParsableCommand {
                static let configuration = CommandConfiguration(
                    commandName: "provision",
                    abstract: "Create a forum space on an authority and add a member"
                )

                @Option(name: .customLong("authority-url"), help: "Authority PDS base URL (default: SWAN_LAB_AUTHORITY_URL or https://swan.test)")
                var authorityURL: String = ""

                @Option(name: .long, help: "Permissioned space URI, e.g. at://did:plc:.../space/blue.catbird.lab.forum/lab-1")
                var space: String

                @Option(name: .customLong("member-did"), help: "Member DID to add to the space")
                var memberDID: String

                @Option(name: .customLong("authority-auth"), help: "Authority auth: none, bearer, or oauth")
                var authorityAuth: String = "oauth"

                @Option(name: .customLong("authority-token-file"), help: "Owner-only file containing the authority bearer token")
                var authorityTokenFile: String?

                @Option(name: .customLong("authority-handle-env"), help: "Environment variable containing the authority OAuth handle")
                var authorityHandleEnvironment = "SWAN_LAB_AUTHORITY_HANDLE"

                @Option(name: .customLong("authority-password-file"), help: "Owner-only file containing the authority OAuth password")
                var authorityPasswordFile: String?

                @Option(name: .customLong("authority-client-id"), help: "Authority OAuth client metadata URL")
                var authorityClientID: String = ""

                @Option(name: .customLong("authority-redirect-uri"), help: "Authority OAuth redirect URI")
                var authorityRedirectURI: String = ""

                @Option(name: .long, parsing: .upToNextOption, help: "OAuth scope to request; repeatable")
                var scope: [String] = ["atproto"]

                @Option(name: .customLong("request-timeout-seconds"))
                var requestTimeoutSeconds: Double = 15

                func run() async throws {
                    let parsedSpace: SpaceURI
                    do { parsedSpace = try SpaceURI(space) }
                    catch { throw ValidationError("--space is not a valid space URI") }
                    let member: String
                    do { member = try AccountIdentifiers.validateDID(memberDID) }
                    catch { throw ValidationError("--member-did is not a canonical DID") }
                    let authority = try await LabLiveSupport.host(
                        label: "authority",
                        url: LabLiveSupport.url(
                            explicit: authorityURL,
                            environment: "SWAN_LAB_AUTHORITY_URL",
                            fallback: "https://swan.test"
                        ),
                        auth: authorityAuth,
                        tokenFile: authorityTokenFile,
                        handleEnvironment: authorityHandleEnvironment,
                        passwordFile: authorityPasswordFile,
                        clientID: authorityClientID,
                        redirectURI: authorityRedirectURI,
                        scopes: scope,
                        timeout: requestTimeoutSeconds,
                        permissionedCommitVerificationKey: nil
                    )
                    try await LabLiveSupport.provisionSpace(
                        authority: authority,
                        space: parsedSpace,
                        member: member
                    )
                    print("FORUM SPACE PROVISIONED: \(parsedSpace.rawValue) member=\(member)")
                }
            }

            /// Writes one post or reply record into the CALLER's own
            /// permissioned repository through `com.atproto.space.putRecord`.
            /// The write is authorized by the caller's OAuth session with a
            /// create scope for the space (mirroring `lab live --mode
            /// permissioned`), never by the read-only space credential.
            struct Post: AsyncParsableCommand {
                static let configuration = CommandConfiguration(
                    commandName: "post",
                    abstract: "Write one forum record into the caller's permissioned repository"
                )

                @Option(name: .customLong("producer-url"), help: "Caller PDS base URL (default: SWAN_LAB_PRODUCER_URL or https://swan.test)")
                var producerURL: String = ""

                @Option(name: .long, help: "Permissioned space URI")
                var space: String

                @Option(name: .long, help: "Record collection (default: blue.catbird.lab.post)")
                var collection: String = Forum.postCollection

                @Option(name: .long, help: "Post text")
                var text: String

                @Option(name: .long, help: "Record key; a sortable TID is generated when absent")
                var rkey: String = ""

                @Option(name: .customLong("reply-to"), help: "Optional at:// record URI of the parent record (writes reply: {root, parent})")
                var replyTo: String = ""

                @Option(name: .customLong("reply-root"), help: "Optional at:// record URI of the thread root; defaults to --reply-to")
                var replyRoot: String = ""

                @Option(name: .long, help: "Repository DID to write (required with bearer auth; defaults to the OAuth subject)")
                var repo: String = ""

                @Option(name: .customLong("producer-auth"), help: "Caller auth: none, bearer, or oauth")
                var producerAuth: String = "oauth"

                @Option(name: .customLong("producer-token-file"), help: "Owner-only file containing the caller bearer token")
                var producerTokenFile: String?

                @Option(name: .customLong("producer-handle-env"), help: "Environment variable containing the caller OAuth handle")
                var producerHandleEnvironment = "SWAN_LAB_PRODUCER_HANDLE"

                @Option(name: .customLong("producer-password-file"), help: "Owner-only file containing the caller OAuth password")
                var producerPasswordFile: String?

                @Option(name: .customLong("producer-client-id"), help: "Caller OAuth client metadata URL")
                var producerClientID: String = ""

                @Option(name: .customLong("producer-redirect-uri"), help: "Caller OAuth redirect URI")
                var producerRedirectURI: String = ""

                @Option(name: .long, parsing: .upToNextOption, help: "OAuth scope to request; repeatable (default: atproto plus the derived space create scope)")
                var scope: [String] = []

                @Option(name: .long, help: "Destination for the sanitized JSON artifact")
                var output: String = "artifacts/forum/post.json"

                @Option(name: .customLong("request-timeout-seconds"))
                var requestTimeoutSeconds: Double = 15

                @Flag(
                    name: .customLong("fail-on-failure"),
                    inversion: .prefixedNo,
                    help: "Return non-zero when the write did not pass (default)"
                )
                var failOnFailure: Bool = true

                func run() async throws {
                    let parsedSpace: SpaceURI
                    do { parsedSpace = try SpaceURI(space) }
                    catch { throw ValidationError("--space is not a valid space URI") }
                    _ = try SpaceRecordURI(
                        space: parsedSpace,
                        author: parsedSpace.authority,
                        collection: collection,
                        rkey: "2"
                    )
                    let normalizedText = text.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !normalizedText.isEmpty, normalizedText.utf8.count <= 4_096 else {
                        throw ValidationError("--text must contain between 1 and 4096 bytes")
                    }
                    var reply: [String: String]?
                    if !replyTo.isEmpty {
                        do { _ = try SpaceRecordURI(replyTo) }
                        catch { throw ValidationError("--reply-to is not a valid at:// record URI") }
                        let root = replyRoot.isEmpty ? replyTo : replyRoot
                        do { _ = try SpaceRecordURI(root) }
                        catch { throw ValidationError("--reply-root is not a valid at:// record URI") }
                        reply = ["root": root, "parent": replyTo]
                    }
                    let requestedScopes = Forum.scopes(
                        requested: scope,
                        space: parsedSpace,
                        action: "create",
                        collection: collection
                    )
                    let producerURL = try LabLiveSupport.url(
                        explicit: producerURL,
                        environment: "SWAN_LAB_PRODUCER_URL",
                        fallback: "https://swan.test"
                    )
                    let hostResult = try await Forum.oauthAwareHost(
                        label: "member",
                        url: producerURL,
                        auth: producerAuth,
                        tokenFile: producerTokenFile,
                        handleEnvironment: producerHandleEnvironment,
                        passwordFile: producerPasswordFile,
                        clientID: producerClientID,
                        redirectURI: producerRedirectURI,
                        scopes: requestedScopes,
                        timeout: requestTimeoutSeconds
                    )
                    let producer = hostResult.host
                    let repositoryDID: String
                    if !repo.isEmpty {
                        do { repositoryDID = try AccountIdentifiers.validateDID(repo) }
                        catch { throw ValidationError("--repo is not a canonical DID") }
                    } else if let subject = hostResult.subject, !subject.isEmpty {
                        repositoryDID = subject
                    } else {
                        throw ValidationError(
                            "post requires --repo with non-OAuth auth, or OAuth auth so the subject DID can be derived"
                        )
                    }
                    let recordKey: String
                    if !rkey.isEmpty {
                        recordKey = rkey
                    } else {
                        recordKey = await TIDGenerator.next()
                    }
                    _ = try SpaceRecordURI(
                        space: parsedSpace,
                        author: repositoryDID,
                        collection: collection,
                        rkey: recordKey
                    )
                    var record: [String: Any] = [
                        "$type": collection,
                        "text": normalizedText,
                        "createdAt": Forum.currentTimestamp(),
                    ]
                    if let reply { record["reply"] = reply }
                    let body = try JSONSerialization.data(
                        withJSONObject: [
                            "space": parsedSpace.rawValue,
                            "repo": repositoryDID,
                            "collection": collection,
                            "rkey": recordKey,
                            "record": record,
                        ],
                        options: [.sortedKeys]
                    )
                    var status = "failed"
                    var errorCode: String?
                    var writtenURI: String?
                    var writtenCID: String?
                    do {
                        let authorization: InteropAuthorization
                        if let provider = producer.authorizationProvider {
                            let path = try producer.client.xrpcPath("com.atproto.space.createRecord")
                            guard let target = URL(
                                string: path,
                                relativeTo: producer.client.http.baseURL
                            )?.absoluteURL else {
                                throw InteropHTTPError.invalidURL
                            }
                            authorization = try await provider(.post, target, body)
                        } else {
                            authorization = producer.authorization
                        }
                        let response = try await producer.client.procedure(
                            "com.atproto.space.createRecord",
                            body: body,
                            authorization: authorization
                        )
                        guard (200 ... 299).contains(response.status) else {
                            errorCode = Forum.responseErrorCode(response)
                            throw ValidationError(
                                "forum post failed (status=\(response.status), error=\(errorCode ?? "unknown"))"
                            )
                        }
                        let output = try StrictJSON.decode(
                            ForumPutRecordResponse.self,
                            from: response.body
                        )
                        writtenURI = output.uri
                        writtenCID = output.cid
                        _ = try SpaceRecordURI(writtenURI ?? "")
                        guard let writtenCID, (try? CID.parse(writtenCID)) != nil else {
                            throw ValidationError("forum post returned an invalid URI/CID")
                        }
                        status = "passed"
                    } catch {
                        if errorCode == nil {
                            errorCode = Forum.errorCode(error)
                        }
                        let artifact = ForumPostArtifact(
                            space: parsedSpace.rawValue,
                            repositoryDID: repositoryDID,
                            collection: collection,
                            rkey: recordKey,
                            uri: writtenURI,
                            cid: writtenCID,
                            status: status,
                            errorCode: errorCode
                        )
                        let outputURL = URL(fileURLWithPath: output)
                        try FileManager.default.createDirectory(
                            at: outputURL.deletingLastPathComponent(),
                            withIntermediateDirectories: true
                        )
                        let encoder = JSONEncoder()
                        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                        try encoder.encode(artifact).write(to: outputURL, options: .atomic)
                        try FileManager.default.setAttributes(
                            [.posixPermissions: 0o600],
                            ofItemAtPath: outputURL.path
                        )
                        print("FORUM POST ARTIFACT WRITTEN: \(outputURL.path) status=\(artifact.status)")
                        guard !failOnFailure || artifact.status == "passed" else {
                            throw ValidationError(
                                "forum post did not pass; inspect \(outputURL.lastPathComponent)"
                            )
                        }
                        return
                    }
                    let artifact = ForumPostArtifact(
                        space: parsedSpace.rawValue,
                        repositoryDID: repositoryDID,
                        collection: collection,
                        rkey: recordKey,
                        uri: writtenURI,
                        cid: writtenCID,
                        status: status,
                        errorCode: errorCode
                    )
                    let outputURL = URL(fileURLWithPath: output)
                    try FileManager.default.createDirectory(
                        at: outputURL.deletingLastPathComponent(),
                        withIntermediateDirectories: true
                    )
                    let encoder = JSONEncoder()
                    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                    try encoder.encode(artifact).write(to: outputURL, options: .atomic)
                    try FileManager.default.setAttributes(
                        [.posixPermissions: 0o600],
                        ofItemAtPath: outputURL.path
                    )
                    print("FORUM POST WRITTEN: \(writtenURI ?? "?") cid=\(writtenCID ?? "?")")
                    print("FORUM POST ARTIFACT WRITTEN: \(outputURL.path) status=\(artifact.status)")
                }
            }

            /// THE SYNCER. Authenticates as the acting user (e.g. Carol),
            /// mints one delegation token at her PDS, exchanges it at the
            /// space authority for ONE space credential, discovers the writer
            /// repos from the authority's `listRepos`, then fetches, verifies,
            /// and durably applies every writer's repo with that single
            /// credential, merges the records into one thread, and prints it.
            struct Thread: AsyncParsableCommand {
                static let configuration = CommandConfiguration(
                    commandName: "thread",
                    abstract: "Sync every writer repo in a forum space and print the merged thread"
                )

                @Option(name: .customLong("consumer-url"), help: "Acting user PDS base URL (default: SWAN_LAB_CONSUMER_URL or https://pds.test)")
                var consumerURL: String = ""

                @Option(name: .customLong("authority-url"), help: "Space authority base URL (default: SWAN_LAB_AUTHORITY_URL or https://swan.test)")
                var authorityURL: String = ""

                @Option(name: .long, help: "Permissioned space URI")
                var space: String

                @Option(name: .customLong("receiver-did"), help: "Managed receiver account DID (the acting user)")
                var receiverDID: String

                @Option(name: .long, help: "Swan data directory containing the receiver database")
                var dataDirectory: String

                @Option(name: .customLong("consumer-auth"), help: "Acting user auth: none, bearer, or oauth")
                var consumerAuth: String = "oauth"

                @Option(name: .customLong("consumer-token-file"), help: "Owner-only file containing the acting user bearer token")
                var consumerTokenFile: String?

                @Option(name: .customLong("consumer-handle-env"), help: "Environment variable containing the acting user OAuth handle")
                var consumerHandleEnvironment = "SWAN_LAB_CONSUMER_HANDLE"

                @Option(name: .customLong("consumer-password-file"), help: "Owner-only file containing the acting user OAuth password")
                var consumerPasswordFile: String?

                @Option(name: .customLong("consumer-client-id"), help: "Acting user OAuth client metadata URL")
                var consumerClientID: String = ""

                @Option(name: .customLong("consumer-redirect-uri"), help: "Acting user OAuth redirect URI")
                var consumerRedirectURI: String = ""

                @Option(name: .long, parsing: .upToNextOption, help: "OAuth scope to request; repeatable (default: atproto plus the derived space read scope)")
                var scope: [String] = []

                @Option(name: .customLong("permissioned-commit-key-env"), help: "Compatibility option only; native reads use SWAN_LAB_KEM_KEYS_FILE or SWAN_LAB_KEM_PUBLIC_KEY")
                var permissionedCommitKeyEnvironment = "SWAN_LAB_PERMISSIONED_COMMIT_KEY"

                @Option(name: .customLong("plc-origin"), help: "PLC directory origin used to discover each writer's repo host (default: https://plc.directory)")
                var plcOrigin: String = PLCClientConfiguration.defaultProductionOrigin.absoluteString

                @Flag(name: .customLong("plc-laboratory"), help: "Allow an explicitly loopback/allowlisted HTTP PLC origin for the lab")
                var plcLaboratory = false

                @Option(name: .customLong("plc-laboratory-allowlisted-host"), help: "Explicit Docker/service DNS host allowed for --plc-laboratory")
                var plcLaboratoryAllowlistedHost: String?

                @Option(name: .customLong("writer-host"), parsing: .upToNextOption, help: "Explicit writer repo host as did=url; repeatable (overrides PLC discovery). Legacy commit-key suffixes are accepted for compatibility and ignored by native reads")
                var writerHost: [String] = []

                @Flag(
                    name: .customLong("full-car-recovery"),
                    inversion: .prefixedNo,
                    help: "Compatibility flag name; perform verified full-STAR replacement when incremental history is unavailable"
                )
                var fullCARRecovery = true

                @Option(name: .long, help: "Destination for the sanitized JSON artifact")
                var output: String = "artifacts/forum/thread.json"

                @Option(name: .customLong("request-timeout-seconds"))
                var requestTimeoutSeconds: Double = 15

                @Flag(
                    name: .customLong("fail-on-failure"),
                    inversion: .prefixedNo,
                    help: "Return non-zero when the thread sync did not pass (default)"
                )
                var failOnFailure: Bool = true

                func run() async throws {
                    let parsedSpace: SpaceURI
                    do { parsedSpace = try SpaceURI(space) }
                    catch { throw ValidationError("--space is not a valid space URI") }
                    let receiver: String
                    do { receiver = try AccountIdentifiers.validateDID(receiverDID) }
                    catch { throw ValidationError("--receiver-did is not a canonical DID") }
                    guard requestTimeoutSeconds > 0,
                          requestTimeoutSeconds <= 120,
                          requestTimeoutSeconds.isFinite else {
                        throw ValidationError("--request-timeout-seconds is invalid")
                    }
                    let dataURL = URL(fileURLWithPath: dataDirectory)
                    let writerHosts = try Forum.writerHostMap(writerHost)
                    Forum.log("forum thread: writer hosts parsed (\(writerHosts.count))")
                    try await Forum.requireActiveManagedAccount(
                        did: receiver,
                        dataDirectory: dataURL
                    )
                    Forum.log("forum thread: receiver account is active")
                    let consumer = try await Forum.oauthAwareHost(
                        label: "consumer",
                        url: LabLiveSupport.url(
                            explicit: consumerURL,
                            environment: "SWAN_LAB_CONSUMER_URL",
                            fallback: "https://pds.test"
                        ),
                        auth: consumerAuth,
                        tokenFile: consumerTokenFile,
                        handleEnvironment: consumerHandleEnvironment,
                        passwordFile: consumerPasswordFile,
                        clientID: consumerClientID,
                        redirectURI: consumerRedirectURI,
                        scopes: Forum.scopes(
                            requested: scope,
                            space: parsedSpace,
                            action: "read",
                            collection: nil
                        ),
                        timeout: requestTimeoutSeconds
                    ).host
                    Forum.log("forum thread: consumer OAuth complete")
                    let authority = try await LabLiveSupport.host(
                        label: "authority",
                        url: LabLiveSupport.url(
                            explicit: authorityURL,
                            environment: "SWAN_LAB_AUTHORITY_URL",
                            fallback: "https://swan.test"
                        ),
                        auth: "none",
                        tokenFile: nil,
                        handleEnvironment: "SWAN_UNUSED",
                        passwordFile: nil,
                        clientID: "",
                        redirectURI: "",
                        scopes: ["atproto"],
                        timeout: requestTimeoutSeconds,
                        permissionedCommitVerificationKey: nil
                    )
                    Forum.log("forum thread: authority host ready")
                    let plc = try Forum.plcClient(
                        origin: plcOrigin,
                        laboratory: plcLaboratory,
                        allowlistedHost: plcLaboratoryAllowlistedHost
                    )
                    Forum.log("forum thread: opening receiver database")
                    let database = try await SQLiteAccountDatabase(
                        dataDirectory: dataURL,
                        did: receiver,
                        openMode: .existingManaged
                    )
                    Forum.log("forum thread: receiver database open")
                    var writerStatuses: [ForumWriterStatus] = []
                    var allRecords: [ForumRecord] = []
                    var failedWriters: [String] = []
                    do {
                        Forum.log("forum thread: exchanging space credential")
                        let credential = try await SpaceCredentialBroker(
                            member: consumer.client,
                            authority: authority.client
                        ).exchange(
                            space: parsedSpace,
                            memberAuthorization: consumer.authorization,
                            memberAuthorizationProvider: consumer.authorizationProvider
                        )
                        Forum.log("forum thread: space credential issued")
                        let credentialAuthorization = InteropAuthorization.spaceCredential(credential)
                        Forum.log("forum thread: listing writers")
                        let writers = try await Forum.listWriters(
                            authority: authority,
                            space: parsedSpace,
                            authorization: credentialAuthorization,
                            timeout: requestTimeoutSeconds
                        )
                        Forum.log("forum thread: writer set contains \(writers.count) writers")
                        for writer in writers {
                            Forum.log("forum thread: syncing writer \(writer)")
                            let writerURL: URL
                            do {
                                writerURL = try await Forum.writerHost(
                                    did: writer,
                                    overrides: writerHosts,
                                    plc: plc
                                )
                            } catch {
                                failedWriters.append(writer)
                                writerStatuses.append(ForumWriterStatus(
                                    did: writer,
                                    host: "<unresolved>",
                                    outcome: "host_unresolved",
                                    revision: nil,
                                    commitment: nil,
                                    recordCount: 0
                                ))
                                continue
                            }
                            // Every writer is authenticated by its dedicated KEM key.
                            let writerKey: PermissionedDataJWTVerificationKey? = nil
                            let source = LiveInteropHost(
                                label: "writer-\(writer)",
                                client: try InteropXRPCClient(
                                    baseURL: writerURL,
                                    timeout: requestTimeoutSeconds,
                                    additionalTrustRootFile: ProcessInfo
                                        .processInfo.environment["SWAN_LAB_CA_CERT_FILE"]
                                        .map { URL(fileURLWithPath: $0) }
                                ),
                                authorization: credentialAuthorization,
                                permissionedCommitVerificationKey: writerKey,
                                permissionedKEMKeyProvider: try LabLiveSupport.kemKeyProvider()
                            )
                            let target = try PermissionedRemoteReplicaTarget(
                                receiverDID: receiver,
                                space: parsedSpace,
                                repositoryDID: writer
                            )
                            let requestID = "forum-\(UUID().uuidString.lowercased())"
                            let applyAuthorized:
                                PermissionedRemoteReplicaIncrementalHTTPOrchestrator
                                .PublicationAuthorization = { operation in
                                    Forum.log("forum thread: apply authorization opening control database")
                                    let control = try await SQLiteControlDatabase(
                                        dataDirectory: dataURL
                                    )
                                    do {
                                        Forum.log("forum thread: apply authorization running operation")
                                        let result = try await control
                                            .withActiveAccountAuthorization(
                                                did: receiver,
                                                operation: operation
                                            )
                                        try await control.close()
                                        Forum.log("forum thread: apply authorization completed")
                                        return result
                                    } catch {
                                        try? await control.close()
                                        throw error
                                    }
                                }
                            let orchestrator =
                                PermissionedRemoteReplicaIncrementalHTTPOrchestrator(
                                    source: source,
                                    store: database,
                                    publicationAuthorization: applyAuthorized
                                )
                            let outcome:
                                PermissionedRemoteReplicaIncrementalSyncOutcome
                            do {
                                outcome = try await orchestrator.synchronize(
                                    target: target,
                                    requestID: requestID,
                                    requestSequence: 1,
                                    appliedAt: Int64(Date().timeIntervalSince1970)
                                )
                            } catch {
                                failedWriters.append(writer)
                                writerStatuses.append(ForumWriterStatus(
                                    did: writer,
                                    host: writerURL.host ?? writerURL.absoluteString,
                                    outcome: Forum.errorCode(error),
                                    revision: nil,
                                    commitment: nil,
                                    recordCount: 0
                                ))
                                continue
                            }
                            var outcomeCode = outcome.code
                            Forum.log("forum thread: sync outcome = \(outcomeCode)")
                            if case .fullCARRecoveryRequired = outcome,
                               fullCARRecovery {
                                Forum.log("forum thread: full-CAR recovery starting for \(writer)")
                                do {
                                    try await Self.recoverWriter(
                                        target: target,
                                        requestID: requestID,
                                        source: source,
                                        receiver: receiver,
                                        dataDirectory: dataURL,
                                        database: database,
                                        timeout: requestTimeoutSeconds
                                    )
                                    outcomeCode = "full_car_applied"
                                } catch {
                                    failedWriters.append(writer)
                                    writerStatuses.append(ForumWriterStatus(
                                        did: writer,
                                        host: writerURL.host ?? writerURL.absoluteString,
                                        outcome: "full_car_failed",
                                        revision: nil,
                                        commitment: nil,
                                        recordCount: 0
                                    ))
                                    continue
                                }
                            }
                            Forum.log("forum thread: reading replica head")
                            let final = try await database
                                .permissionedRemoteReplicaHead(target: target)
                            Forum.log("forum thread: replica head read")
                            let snapshots = try await database
                                .permissionedRemoteReplicaRecords(target: target)
                            Forum.log("forum thread: replica records read (\(snapshots.count))")
                            var writerRecords: [ForumRecord] = []
                            for snapshot in snapshots {
                                guard snapshot.uri.collection == Forum.postCollection
                                        || snapshot.uri.collection == Forum.replyCollection
                                else { continue }
                                writerRecords.append(
                                    try ForumRecordDecoding.decode(
                                        uri: snapshot.uri,
                                        cid: snapshot.cid,
                                        revision: 0,
                                        value: snapshot.value
                                    )
                                )
                            }
                            allRecords.append(contentsOf: writerRecords)
                            writerStatuses.append(ForumWriterStatus(
                                did: writer,
                                host: writerURL.host ?? writerURL.absoluteString,
                                outcome: outcomeCode,
                                revision: final?.wireRevision.toString(),
                                commitment: final.map { Hex.encode($0.commitment) },
                                recordCount: writerRecords.count
                            ))
                            Forum.log("forum thread: writer \(writer) synced (\(outcomeCode), \(writerRecords.count) records)")
                        }
                    } catch {
                        try? await database.close()
                        let thread = ForumThread(roots: [], unlinked: [])
                        let artifact = ForumThreadArtifactBuilder.artifact(
                            profileID: OfflineProtocolProfileVerifier.stableProfileID,
                            space: parsedSpace.rawValue,
                            status: "failed",
                            errorCode: Forum.errorCode(error),
                            writers: writerStatuses,
                            thread: thread
                        )
                        try Forum.writeArtifact(artifact, to: URL(fileURLWithPath: output))
                        print("FORUM THREAD ARTIFACT WRITTEN: \(URL(fileURLWithPath: output).path) status=failed")
                        guard !failOnFailure else {
                            throw ValidationError(
                                "forum thread sync did not pass; inspect \(URL(fileURLWithPath: output).lastPathComponent)"
                            )
                        }
                        return
                    }
                    try await database.close()
                    let thread = ForumThreadMerger.merge(allRecords)
                    let passed = failedWriters.isEmpty
                    let artifact = ForumThreadArtifactBuilder.artifact(
                        profileID: OfflineProtocolProfileVerifier.stableProfileID,
                        space: parsedSpace.rawValue,
                        status: passed ? "passed" : "failed",
                        errorCode: failedWriters.isEmpty ? nil : "writer_sync_failed",
                        writers: writerStatuses,
                        thread: thread
                    )
                    let outputURL = URL(fileURLWithPath: output)
                    try Forum.writeArtifact(artifact, to: outputURL)
                    print("FORUM THREAD: \(thread.roots.count) roots, \(thread.replyCount) replies, \(thread.unlinked.count) unlinked")
                    print(ForumThreadRender.render(thread))
                    print("FORUM THREAD ARTIFACT WRITTEN: \(outputURL.path) status=\(artifact.status)")
                    guard !failOnFailure || passed else {
                        throw ValidationError(
                            "forum thread sync did not pass; inspect \(outputURL.lastPathComponent)"
                        )
                    }
                }

                private static func recoverWriter(
                    target: PermissionedRemoteReplicaTarget,
                    requestID: String,
                    source: LiveInteropHost,
                    receiver: String,
                    dataDirectory: URL,
                    database: SQLiteAccountDatabase,
                    timeout: Double
                ) async throws {
                    let limits = SpaceCARRecoveryLimits.standard
                    let temporaryDirectory = FileManager.default
                        .temporaryDirectory.appending(
                            path: "swan-forum-recovery-\(UUID().uuidString)",
                            directoryHint: .isDirectory
                        )
                    try FileManager.default.createDirectory(
                        at: temporaryDirectory,
                        withIntermediateDirectories: false,
                        attributes: [.posixPermissions: 0o700]
                    )
                    defer {
                        try? FileManager.default.removeItem(at: temporaryDirectory)
                    }
                    let spoolAdmission = try PublicRepositorySpoolAdmission(
                        maximumGlobalBytes: limits.maximumCARBytes,
                        maximumPerAccountBytes: limits.maximumCARBytes
                    )
                    let recoveryAuthorization:
                        PermissionedRemoteReplicaRecoveryOrchestrator
                        .PublicationAuthorization = { operation in
                            let control = try await SQLiteControlDatabase(
                                dataDirectory: dataDirectory
                            )
                            do {
                                let result = try await control
                                    .withActiveAccountAuthorization(
                                        did: receiver,
                                        operation: operation
                                    )
                                try await control.close()
                                return result
                            } catch {
                                try? await control.close()
                                throw error
                            }
                        }
                    _ = try await LiveInteropRunner
                        .recoverPermissionedRepository(
                            target: target,
                            requestID: "\(requestID)-full-car",
                            sourceHost: source,
                            receiverDatabase: database,
                            expiresAt:
                                Int64(Date().timeIntervalSince1970) + 300,
                            temporaryDirectory: temporaryDirectory,
                            spoolAdmission: spoolAdmission,
                            limits: limits,
                            publicationAuthorization: recoveryAuthorization,
                            now: { Int64(Date().timeIntervalSince1970) }
                        )
                    _ = timeout
                }
            }

            /// Builds the default OAuth scope set for a space action, allowing
            /// operator overrides to replace it entirely.
            private static func scopes(
                requested: [String],
                space: SpaceURI,
                action: String,
                collection: String?
            ) -> [String] {
                let normalized = requested.map {
                    $0.trimmingCharacters(in: .whitespacesAndNewlines)
                }.filter { !$0.isEmpty }
                guard normalized.isEmpty else { return normalized }
                var result = ["atproto"]
                var scope = "space:\(space.spaceType)?authority=\(space.authority)&skey=\(space.skey)&action=\(action)"
                if let collection {
                    scope += "&collection=\(collection)"
                }
                result.append(scope)
                return result
            }

            /// OAuth-authorized host creation that also surfaces the token
            /// subject DID (needed as the `repo` for putRecord). Non-OAuth
            /// auth reuses `LabLiveSupport.host` unchanged.
            private static func oauthAwareHost(
                label: String,
                url: URL,
                auth: String,
                tokenFile: String?,
                handleEnvironment: String,
                passwordFile: String?,
                clientID: String,
                redirectURI: String,
                scopes: [String],
                timeout: Double
            ) async throws -> (host: LiveInteropHost, subject: String?) {
                let normalized = auth.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                guard normalized == "oauth" else {
                    let host = try await LabLiveSupport.host(
                        label: label,
                        url: url,
                        auth: normalized,
                        tokenFile: tokenFile,
                        handleEnvironment: handleEnvironment,
                        passwordFile: passwordFile,
                        clientID: clientID,
                        redirectURI: redirectURI,
                        scopes: scopes,
                        timeout: timeout,
                        permissionedCommitVerificationKey: nil
                    )
                    return (host, nil)
                }
                try requireCredentialSafeTransport(url)
                guard let passwordFile, !passwordFile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    throw ValidationError("live OAuth password file is unavailable")
                }
                let password = try readOwnerOnlySecretFile(
                    URL(fileURLWithPath: passwordFile),
                    validationMessage: "live OAuth password file is unavailable"
                )
                let handle = try LabLiveSupport.environmentValue(
                    handleEnvironment,
                    label: "OAuth handle"
                )
                let clientIDURL = try LabLiveSupport.requiredURL(
                    clientID,
                    label: "OAuth client metadata",
                    allowQuery: true
                )
                let redirectURL = try LabLiveSupport.requiredURL(
                    redirectURI,
                    label: "OAuth redirect"
                )
                let requestedScopes = Set(scopes.map {
                    $0.trimmingCharacters(in: .whitespacesAndNewlines)
                }.filter { !$0.isEmpty })
                guard !requestedScopes.isEmpty else {
                    throw ValidationError("OAuth scope must not be empty")
                }
                let additionalTrustRootFile = ProcessInfo.processInfo.environment[
                    "SWAN_LAB_CA_CERT_FILE"
                ].map { URL(fileURLWithPath: $0) }
                let oauth = try SwanOAuthLabClient(
                    issuer: url,
                    clientID: clientIDURL,
                    redirectURI: redirectURL,
                    timeout: timeout,
                    additionalTrustRootFile: additionalTrustRootFile
                )
                let token = try await oauth.authorizationCode(
                    handle: handle,
                    password: password,
                    scopes: requestedScopes
                )
                let provider = await oauth.authorizationProvider(for: token)
                let host = LiveInteropHost(
                    label: label,
                    client: try InteropXRPCClient(
                        baseURL: url,
                        timeout: timeout,
                        additionalTrustRootFile: additionalTrustRootFile
                    ),
                    authorizationProvider: provider
                )
                return (host, token.subject)
            }

            /// One explicit `--writer-host` override: the writer repo host URL
            /// and an optional legacy commit key retained only for compatibility.
            private struct WriterHostOverride: Sendable, Equatable {
                let url: URL
                let commitVerificationKey: String?
            }

            /// Parses repeatable `did=url` writer-host overrides. Each value
            /// may retain a legacy `:did:key:z...` commit-key suffix. Parsing
            /// still validates that historical syntax; current reads authenticate
            /// with the dedicated KEM provider and do not consume this key.
            private static func writerHostMap(
                _ values: [String]
            ) throws -> [String: WriterHostOverride] {
                var result: [String: WriterHostOverride] = [:]
                for raw in values {
                    let pieces = raw.split(
                        separator: "=",
                        maxSplits: 1,
                        omittingEmptySubsequences: false
                    )
                    guard pieces.count == 2 else {
                        throw ValidationError("--writer-host values must use did=url[:did:key:z...]")
                    }
                    let did = String(pieces[0])
                    let canonical: String
                    do { canonical = try AccountIdentifiers.validateDID(did) }
                    catch { throw ValidationError("--writer-host DID is not canonical") }
                    guard result[canonical] == nil else {
                        throw ValidationError("--writer-host contains a duplicate DID")
                    }
                    let value = String(pieces[1])
                    let override: WriterHostOverride
                    if let keyRange = value.range(
                        of: ":did:key:z",
                        options: .backwards
                    ) {
                        let urlString = String(value[..<keyRange.lowerBound])
                        let keyString = String(value[keyRange.lowerBound...].dropFirst())
                        guard let url = try? LabLiveSupport.requiredURL(
                            urlString,
                            label: "writer host"
                        ), (try? LabLiveSupport.decodeCommitVerificationKey(keyString)) != nil else {
                            throw ValidationError(
                                "--writer-host contains an invalid URL or commit key"
                            )
                        }
                        override = WriterHostOverride(
                            url: url,
                            commitVerificationKey: keyString
                        )
                    } else {
                        guard let url = try? LabLiveSupport.requiredURL(
                            value,
                            label: "writer host"
                        ) else {
                            throw ValidationError("--writer-host contains an invalid URL")
                        }
                        override = WriterHostOverride(
                            url: url,
                            commitVerificationKey: nil
                        )
                    }
                    result[canonical] = override
                }
                return result
            }

            private static func plcClient(
                origin: String,
                laboratory: Bool,
                allowlistedHost: String?
            ) throws -> (any PLCClient)? {
                guard let originURL = URL(string: origin) else {
                    throw ValidationError("--plc-origin must be a URL")
                }
                let configuration: PLCClientConfiguration
                do {
                    if laboratory {
                        configuration = try .laboratory(
                            origin: originURL,
                            allowlistedHost: allowlistedHost
                        )
                    } else {
                        guard allowlistedHost == nil else {
                            throw ValidationError(
                                "--plc-laboratory-allowlisted-host requires --plc-laboratory"
                            )
                        }
                        configuration = try .production(origin: originURL)
                    }
                    return try PLCDirectoryClient(configuration: configuration)
                } catch let error as ValidationError {
                    throw error
                } catch {
                    throw ValidationError("--plc-origin is not an allowed PLC origin")
                }
            }

            /// Resolves one writer's repo host: explicit override first, then
            /// the writer DID's `#atproto_pds` service endpoint from PLC.
            private static func writerHost(
                did: String,
                overrides: [String: WriterHostOverride],
                plc: (any PLCClient)?
            ) async throws -> URL {
                if let override = overrides[did] {
                    return override.url
                }
                guard let plc else {
                    throw SwanError.unavailable(
                        "writer host for \(did) requires a PLC origin or --writer-host override"
                    )
                }
                let state: PLCDocumentData
                do {
                    state = try await plc.fetchState(did: did)
                } catch {
                    throw SwanError.unavailable(
                        "writer host for \(did) could not be resolved from PLC"
                    )
                }
                guard state.did == did,
                      let endpoint = state.services["atproto_pds"]?.endpoint,
                      let url = try? LabLiveSupport.requiredURL(
                        endpoint,
                        label: "writer host"
                      ) else {
                    throw SwanError.unavailable(
                        "writer host for \(did) is missing its atproto_pds service"
                    )
                }
                return url
            }

            /// Pages `com.atproto.space.listWriters` at the authority with the
            /// space credential and returns the active writer DID set.
            private static func listWriters(
                authority: LiveInteropHost,
                space: SpaceURI,
                authorization: InteropAuthorization,
                timeout: Double
            ) async throws -> [String] {
                _ = timeout
                var writers: [String] = []
                var cursor: String?
                while true {
                    var query = [
                        "space": space.rawValue,
                        "limit": "100",
                    ]
                    if let cursor { query["cursor"] = cursor }
                    let response = try await authority.client.query(
                        "com.atproto.space.listWriters",
                        query: query,
                        authorization: authorization
                    )
                    guard (200 ... 299).contains(response.status),
                          response.header("content-type")?.lowercased()
                            .contains("json") == true else {
                        throw InteropHTTPError.unexpectedStatus(response.status)
                    }
                    let output = try StrictJSON.decode(
                        ForumListWritersResponse.self,
                        from: response.body
                    )
                    for entry in output.repos {
                        let did: String
                        do { did = try AccountIdentifiers.validateDID(entry.repo) }
                        catch {
                            throw ValidationError("listWriters returned a non-canonical writer DID")
                        }
                        switch entry.type {
                        case "com.atproto.space.defs#repoWrite":
                            if !writers.contains(did) { writers.append(did) }
                        case "com.atproto.space.defs#repoRemoved":
                            writers.removeAll { $0 == did }
                        default:
                            throw ValidationError("listWriters returned an unknown entry type")
                        }
                    }
                    // atproto#5574: every nonempty page returns its last
                    // spaceRev as the cursor; an empty page (which omits it)
                    // ends the listing. A repo updated mid-listing can
                    // reappear, so DIDs are de-duplicated above.
                    guard !output.repos.isEmpty,
                          let next = output.cursor, !next.isEmpty else { break }
                    cursor = next
                }
                return writers
            }

            private static func requireActiveManagedAccount(
                did: String,
                dataDirectory: URL
            ) async throws {
                let control = try await SQLiteControlDatabase(
                    dataDirectory: dataDirectory
                )
                do {
                    guard let account = try await control.account(did: did) else {
                        throw ValidationError(
                            "receiver account is not managed by this Swan data directory"
                        )
                    }
                    guard account.status.authorizesAccount else {
                        throw ValidationError("receiver account is not active")
                    }
                    try await control.close()
                } catch {
                    try? await control.close()
                    throw error
                }
            }

            /// Emits one bounded stage marker on stderr. The thread syncer is
            /// a lab diagnostic surface; its stdout stays clean for the
            /// rendered thread and sanitized artifact.
            private static func log(_ message: String) {
                FileHandle.standardError.write(Data(("[forum] \(message)\n").utf8))
            }

            private static func writeArtifact(
                _ artifact: ForumThreadArtifact,
                to outputURL: URL
            ) throws {
                try FileManager.default.createDirectory(
                    at: outputURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                try encoder.encode(artifact).write(to: outputURL, options: .atomic)
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: outputURL.path
                )
            }

            private static func currentTimestamp() -> String {
                let formatter = ISO8601DateFormatter()
                formatter.formatOptions = [.withInternetDateTime]
                return formatter.string(from: Date())
            }

            private static func responseErrorCode(
                _ response: InteropHTTPResponse
            ) -> String? {
                guard let object = try? JSONSerialization.jsonObject(
                    with: response.body
                ) as? [String: Any] else { return nil }
                return object["error"] as? String
            }

            private static func errorCode(_ error: Error) -> String {
                if let error = error as? InteropHTTPError {
                    switch error {
                    case .invalidURL: return "InvalidURL"
                    case .responseTooLarge: return "ResponseTooLarge"
                    case .unexpectedRedirect: return "UnexpectedRedirect"
                    case .unexpectedContentType: return "UnexpectedContentType"
                    case let .unexpectedStatus(status): return "HTTP\(status)"
                    case .transportFailure: return "TransportFailure"
                    case .fileFailure: return "FileFailure"
                    case .spaceCredentialRevoked: return "CredentialRevoked"
                    }
                }
                if let error = error as? ValidationError {
                    return "InvalidRequest"
                }
                if let error = error as? SpaceCARStreamingError {
                    return "CARStreamingFailure"
                }
                return "InteropFailure"
            }
        }

        struct Matrix: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Run multiple interoperability fault modes and write one sanitized artifact per mode"
            )
            @Option(name: .long, help: "Scenario identifier (letters, numbers, hyphen, and underscore only)")
            var name: String = "reference-matrix"

            @Option(
                name: .long,
                parsing: .upToNextOption,
                help: "Repeatable fault mode: normal, offline, disconnected, delayed, duplicated, reordered, or corrupted"
            )
            var fault: [String] = []

            @Option(name: .long, help: "Directory for per-mode output JSON artifacts")
            var outputDirectory: String = "artifacts"

            @Option(name: .long, help: "Swan base URL for scenario probes (default: https://swan.test)")
            var swanBaseURL: String = ""

            @Option(name: .long, help: "Reference PDS base URL for scenario probes (default: https://pds.test)")
            var referenceBaseURL: String = ""

            @Option(name: .long, help: "Per-request timeout in seconds for scenario probes")
            var requestTimeoutSeconds: Double = 8

            @Flag(name: .long, help: "Require strict cross-host convergence for every probed endpoint")
            var strictConvergence: Bool = false

            @Option(
                name: .long,
                parsing: .upToNextOption,
                help: "Repeatable allowlist for strict-convergence mismatches (path or METHOD path)")
            var allowedConvergenceDivergences: [String] = []

            @Flag(
                name: .customLong("fail-on-failure"),
                inversion: .prefixedNo,
                help: "Return non-zero when any matrix cell is not passed (default; use --no-fail-on-failure only for diagnostics)"
            )
            var failOnFailure: Bool = true

            func run() async throws {
                let normalizedScenario = name.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !normalizedScenario.isEmpty,
                      normalizedScenario.unicodeScalars.allSatisfy({
                          CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_")).contains($0)
                      }) else {
                    throw ValidationError("matrix scenario must be an alphanumeric identifier using only letters, numbers, '-' and '_'")
                }

                let requestedFaults = fault.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
                let modes: [String] = requestedFaults.isEmpty
                    ? ["normal", "delayed", "duplicated", "reordered", "offline", "disconnected", "corrupted"]
                    : requestedFaults

                let swanURLString = !swanBaseURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    ? swanBaseURL
                    : ProcessInfo.processInfo.environment["SWAN_SCENARIO_SWAN_URL"] ?? "https://swan.test"
                let referenceURLString = !referenceBaseURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    ? referenceBaseURL
                    : ProcessInfo.processInfo.environment["SWAN_SCENARIO_REFERENCE_URL"] ?? "https://pds.test"

                guard let swanURL = URL(string: swanURLString), let referenceURL = URL(string: referenceURLString) else {
                    throw ValidationError("lab matrix URL is invalid")
                }

                let runtimeConfiguration = InteropScenarioRunner.RuntimeConfiguration(
                    swanBaseURL: swanURL,
                    referenceBaseURL: referenceURL,
                    timeoutInterval: requestTimeoutSeconds,
                    strictConvergence: strictConvergence,
                    allowedConvergenceDivergences: Set(allowedConvergenceDivergences.map {
                        $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                    })
                )

                let outputDirectoryURL = URL(fileURLWithPath: outputDirectory)
                try FileManager.default.createDirectory(
                    at: outputDirectoryURL,
                    withIntermediateDirectories: true
                )

                let encoder = JSONEncoder()
                encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                var hadFailure = false
                var writtenArtifacts: [String] = []

                for rawFault in modes {
                    let matrixMode: [FaultMode]
                    if rawFault == "normal" {
                        matrixMode = []
                    } else if let faultMode = FaultMode(rawValue: rawFault) {
                        matrixMode = [faultMode]
                    } else {
                        throw ValidationError("unsupported lab fault mode")
                    }

                    let scenarioName = "\(normalizedScenario)-\(rawFault)"
                    let artifact = await InteropScenarioRunner.execute(
                        scenario: scenarioName,
                        faultModes: matrixMode,
                        runtime: runtimeConfiguration
                    )
                    let outputURL = outputDirectoryURL.appending(path: "\(scenarioName).json")
                    try encoder.encode(artifact).write(to: outputURL, options: .atomic)
                    writtenArtifacts.append(outputURL.lastPathComponent)
                    print("INTEROP SCENARIO ARTIFACT WRITTEN: \(outputURL.lastPathComponent) status=\(artifact.status)")
                    if artifact.status != "passed" {
                        hadFailure = true
                    }
                }

                if failOnFailure && hadFailure {
                    throw ValidationError("interop matrix did not pass; inspect \(writtenArtifacts)")
                }
            }
        }
    }
}

private enum LabLiveSupport {
    static func identifier(_ rawValue: String, label: String) throws -> String {
        let value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty,
              value.unicodeScalars.allSatisfy({
                  CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_" )).contains($0)
              }) else {
            throw ValidationError("\(label) must be an alphanumeric identifier using only letters, numbers, '-' and '_'")
        }
        return value
    }

    static func url(
        explicit: String,
        environment: String,
        fallback: String
    ) throws -> URL {
        let raw = explicit.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? (ProcessInfo.processInfo.environment[environment] ?? fallback)
            : explicit
        guard let url = URL(string: raw),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil else {
            throw ValidationError("live endpoint URL is invalid")
        }
        return url
    }

    static func requiredURL(
        _ raw: String,
        label: String,
        allowQuery: Bool = false
    ) throws -> URL {
        guard let url = URL(string: raw),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              components.host?.isEmpty == false,
              components.user == nil, components.password == nil,
              (allowQuery || components.query == nil), components.fragment == nil else {
            throw ValidationError("\(label) URL is invalid")
        }
        return url
    }

    static func host(
        label: String,
        url: URL,
        auth: String,
        tokenFile: String?,
        handleEnvironment: String,
        passwordFile: String?,
        clientID: String,
        redirectURI: String,
        scopes: [String],
        timeout: Double,
        permissionedKEMKeyProvider: (@Sendable (String, Bool) async throws -> String)? = nil,
        permissionedCommitVerificationKey: PermissionedDataJWTVerificationKey? = nil
    ) async throws -> LiveInteropHost {
        guard timeout > 0, timeout <= 120, timeout.isFinite else {
            throw ValidationError("--request-timeout-seconds is invalid")
        }
        let additionalTrustRootFile = ProcessInfo.processInfo.environment[
            "SWAN_LAB_CA_CERT_FILE"
        ].map { URL(fileURLWithPath: $0) }
        let client = try InteropXRPCClient(
            baseURL: url,
            timeout: timeout,
            additionalTrustRootFile: additionalTrustRootFile
        )
        switch auth.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "none":
            return LiveInteropHost(
                label: label,
                client: client,
                permissionedCommitVerificationKey: permissionedCommitVerificationKey,
                permissionedKEMKeyProvider: try permissionedKEMKeyProvider ?? LabLiveSupport.kemKeyProvider()
            )
        case "bearer":
            try requireCredentialSafeTransport(url)
            guard let tokenFile, !tokenFile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw ValidationError("live bearer token file is unavailable")
            }
            let token = try readOwnerOnlySecretFile(
                URL(fileURLWithPath: tokenFile),
                validationMessage: "live bearer token file is unavailable"
            )
            return LiveInteropHost(
                label: label,
                client: client,
                authorization: .bearer(token: token),
                permissionedCommitVerificationKey: permissionedCommitVerificationKey,
                permissionedKEMKeyProvider: try permissionedKEMKeyProvider ?? LabLiveSupport.kemKeyProvider()
            )
        case "oauth":
            try requireCredentialSafeTransport(url)
            guard let passwordFile, !passwordFile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw ValidationError("live OAuth password file is unavailable")
            }
            let password = try readOwnerOnlySecretFile(
                URL(fileURLWithPath: passwordFile),
                validationMessage: "live OAuth password file is unavailable"
            )
            let handle = try environmentValue(handleEnvironment, label: "OAuth handle")
            // The AT Protocol localhost development client encodes its
            // requested scope and redirect URI in the client-id query. Remote
            // metadata URLs remain query-free and are validated by Swan's
            // metadata fetcher.
            let clientIDURL = try requiredURL(
                clientID,
                label: "OAuth client metadata",
                allowQuery: true
            )
            let redirectURL = try requiredURL(redirectURI, label: "OAuth redirect")
            let requestedScopes = Set(scopes.map {
                $0.trimmingCharacters(in: .whitespacesAndNewlines)
            }.filter { !$0.isEmpty })
            guard !requestedScopes.isEmpty else {
                throw ValidationError("OAuth scope must not be empty")
            }
            let oauth = try SwanOAuthLabClient(
                issuer: url,
                clientID: clientIDURL,
                redirectURI: redirectURL,
                timeout: timeout,
                additionalTrustRootFile: additionalTrustRootFile
            )
            let token = try await oauth.authorizationCode(
                handle: handle,
                password: password,
                scopes: requestedScopes
            )
            let provider = await oauth.authorizationProvider(for: token)
            return LiveInteropHost(
                label: label,
                client: client,
                authorizationProvider: provider,
                permissionedCommitVerificationKey: permissionedCommitVerificationKey,
                permissionedKEMKeyProvider: try permissionedKEMKeyProvider ?? LabLiveSupport.kemKeyProvider()
            )
        default:
            throw ValidationError("live auth must be none, bearer, or oauth")
        }
    }

    /// Dedicated public KEM pins for the disposable lab. The JSON file maps
    /// repository DIDs to did:key values and is re-read on every resolution,
    /// including the forced refresh after a MAC mismatch. Signing pins are
    /// deliberately not a fallback.
    static func kemKeyProvider() throws -> (@Sendable (String, Bool) async throws -> String)? {
        let env = ProcessInfo.processInfo.environment
        let file = env["SWAN_LAB_KEM_KEYS_FILE"]
        let single = env["SWAN_LAB_KEM_PUBLIC_KEY"]
        guard file != nil || single != nil else { return nil }
        return { did, _ in
            let value: String
            if let file {
                let bytes = try Data(contentsOf: URL(fileURLWithPath: file))
                guard bytes.count <= 64 * 1024,
                      let selected = try JSONDecoder().decode([String: String].self, from: bytes)[did] else {
                    throw SwanError.unavailable("laboratory KEM key pin is unavailable")
                }
                value = selected
            } else if let single { value = single }
            else { throw SwanError.unavailable("laboratory KEM key pin is unavailable") }
            _ = try P256DIDKey(value)
            return value
        }
    }

    static func permissionedCommitVerificationKey(
        environment: String
    ) throws -> PermissionedDataJWTVerificationKey {
        try decodeCommitVerificationKey(
            environmentValue(environment, label: "permissioned commit public key")
        )
    }

    /// Reads the same environment variable as `permissionedCommitVerificationKey`
    /// but treats an absent value as an explicit "no global key" choice, so
    /// per-writer override keys can be the only configured keys.
    static func optionalPermissionedCommitVerificationKey(
        environment: String
    ) throws -> PermissionedDataJWTVerificationKey? {
        guard let configured = ProcessInfo.processInfo.environment[environment],
              !configured.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return nil
        }
        return try decodeCommitVerificationKey(configured)
    }

    static func decodeCommitVerificationKey(
        _ configured: String
    ) throws -> PermissionedDataJWTVerificationKey {
        // Interop runners may supply the repository's canonical PLC
        // verification method directly.  Decode the multicodec before the
        // legacy base64 forms so curve selection remains bound to the
        // published key rather than to an operator-supplied algorithm label.
        if configured.hasPrefix("did:key:z") {
            do {
                switch try PLCDIDKeyCodec.decode(configured) {
                case let .p256(publicKey):
                    return .p256(publicKey)
                case let .secp256k1(publicKey):
                    return try PermissionedDataJWTVerificationKey(
                        secp256k1PublicKey: publicKey
                    )
                }
            } catch {
                throw ValidationError("permissioned commit did:key is invalid")
            }
        }
        let pieces = configured.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        let algorithm: String
        let encoded: String
        switch pieces.count {
        case 1:
            algorithm = "ES256K"
            encoded = String(pieces[0])
        case 2:
            algorithm = String(pieces[0]).uppercased()
            encoded = String(pieces[1])
        default:
            throw ValidationError("permissioned commit public key is invalid")
        }
        guard algorithm == "ES256" || algorithm == "ES256K",
              let data = Data(base64URLEncoded: encoded),
              data.base64URLEncodedString() == encoded else {
            throw ValidationError("permissioned commit public key is not canonical base64url")
        }
        do {
            if algorithm == "ES256" {
                return .p256(try P256.Signing.PublicKey(x963Representation: data))
            }
            return try PermissionedDataJWTVerificationKey(secp256k1PublicKey: data)
        } catch {
            throw ValidationError("permissioned commit public key is invalid")
        }
    }

    static func body(at url: URL) throws -> Data {
        try readBoundedRegularFileNoFollow(
            url,
            maximumBytes: 2 * 1024 * 1024,
            validationMessage: "live body file is unavailable"
        )
    }

    static func query(_ rawValues: [String]) throws -> [String: String] {
        var result: [String: String] = [:]
        for raw in rawValues {
            let pieces = raw.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard pieces.count == 2 else {
                throw ValidationError("--read-query values must use key=value")
            }
            let key = String(pieces[0])
            let value = String(pieces[1])
            guard !key.isEmpty, key.utf8.count <= 256, value.utf8.count <= 4_096,
                  result[key] == nil else {
                throw ValidationError("--read-query contains an invalid or duplicate key")
            }
            result[key] = value
        }
        for required in ["space", "repo", "collection", "rkey"] {
            guard result[required]?.isEmpty == false else {
                throw ValidationError("permissioned live mode requires --read-query \(required)=...")
            }
        }
        return result
    }

    static func provisionSpace(
        authority: LiveInteropHost,
        space: SpaceURI,
        member rawMember: String
    ) async throws {
        let member: String
        do {
            member = try AccountIdentifiers.validateDID(rawMember)
        } catch {
            throw ValidationError("--read-query repo must be a canonical member DID")
        }
        guard authority.authorizationProvider != nil || authority.authorization != .none else {
            throw ValidationError("--consumer-auth oauth is required with --provision-space")
        }

        let createBody = try JSONSerialization.data(
            withJSONObject: [
                "spaceType": space.spaceType,
                "skey": space.skey,
                "policy": ["$type": "com.atproto.memberspace.policy"],
            ],
            options: [.sortedKeys]
        )
        let create = try await authorizedProcedure(
            host: authority,
            nsid: "com.atproto.space.createSpace",
            body: createBody
        )
        guard (200 ... 299).contains(create.status) ||
            responseError(create) == "SpaceAlreadyExists" else {
            let error = responseError(create) ?? "unknown"
            throw ValidationError(
                "permissioned space creation failed (status=\(create.status), error=\(error))"
            )
        }

        let putBody = try JSONSerialization.data(
            withJSONObject: [
                "space": space.rawValue,
                "members": [["did": member, "read": true, "write": true]],
            ],
            options: [.sortedKeys]
        )
        let put = try await authorizedProcedure(
            host: authority,
            nsid: "com.atproto.memberspace.putMembers",
            body: putBody
        )
        guard (200 ... 299).contains(put.status) else {
            let error = responseError(put) ?? "unknown"
            throw ValidationError(
                "permissioned space membership failed (status=\(put.status), error=\(error))"
            )
        }
    }

    private static func authorizedProcedure(
        host: LiveInteropHost,
        nsid: String,
        body: Data
    ) async throws -> InteropHTTPResponse {
        let path = try host.client.xrpcPath(nsid)
        guard let target = URL(string: path, relativeTo: host.client.http.baseURL)?.absoluteURL else {
            throw ValidationError("permissioned setup target is invalid")
        }
        let authorization: InteropAuthorization
        if let provider = host.authorizationProvider {
            authorization = try await provider(.post, target, body)
        } else {
            authorization = host.authorization
        }
        return try await host.client.procedure(
            nsid,
            body: body,
            authorization: authorization
        )
    }

    private static func responseError(_ response: InteropHTTPResponse) -> String? {
        guard let object = try? JSONSerialization.jsonObject(with: response.body)
            as? [String: Any] else { return nil }
        return object["error"] as? String
    }

    static func environmentValue(_ name: String, label: String) throws -> String {
        guard name.utf8.count <= 128,
              name.utf8.allSatisfy({
                  ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x5f
              }),
              let value = ProcessInfo.processInfo.environment[name],
              !value.isEmpty else {
            throw ValidationError("live \(label) environment variable is unavailable")
        }
        return value
    }
}

private struct AnyEncodable: Encodable {
    private let encodeValue: (Encoder) throws -> Void

    init(_ value: any Encodable) {
        encodeValue = value.encode(to:)
    }

    func encode(to encoder: Encoder) throws {
        try encodeValue(encoder)
    }
}

/// Minimal wire shapes for the forum commands. The space layer is
/// collection-agnostic and these endpoints are already covered by the
/// profile-pinned generated client; these local decoders are intentionally
/// limited to the fields the forum CLI needs so the `swan` executable does
/// not need a direct dependency on the generated wire module.
private struct ForumPutRecordResponse: Decodable {
    let uri: String
    let cid: String
}

private struct ForumListWritersResponse: Decodable {
    struct Repo: Decodable {
        let type: String
        let repo: String

        enum CodingKeys: String, CodingKey {
            case type = "$type"
            case repo
        }
    }

    let cursor: String?
    let repos: [Repo]
}

/// Sanitized artifact for one `forum post` write. Contains only the space,
/// repository DID, collection, key, and returned URI/CID; never credentials,
/// tokens, or DPoP proofs.
private struct ForumPostArtifact: Encodable {
    let profileID: String
    let space: String
    let repositoryDID: String
    let collection: String
    let rkey: String
    let uri: String?
    let cid: String?
    let status: String
    let errorCode: String?
    let fixturePolicy: String

    init(
        space: String,
        repositoryDID: String,
        collection: String,
        rkey: String,
        uri: String?,
        cid: String?,
        status: String,
        errorCode: String?
    ) {
        profileID = OfflineProtocolProfileVerifier.stableProfileID
        self.space = space
        self.repositoryDID = repositoryDID
        self.collection = collection
        self.rkey = rkey
        self.uri = uri
        self.cid = cid
        self.status = status
        self.errorCode = errorCode
        fixturePolicy = "counts, DIDs, CIDs, and record keys only; no credentials, tokens, or DPoP proofs"
    }
}

private struct RelayCARInspectionView: Encodable {
    let did: String
    let revision: String
    let commitCID: String
    let dataCID: String
    let mstDigest: String
    let projectionDigest: String

    init(snapshot: RelayRepositorySnapshot) {
        did = snapshot.did
        revision = snapshot.revision
        commitCID = snapshot.commitCID.string
        dataCID = snapshot.dataCID.string
        mstDigest = snapshot.mstDigest
        projectionDigest = RelayRepositoryDigest.projection(snapshot.records)
    }
}

private struct LocalAccountInstallationView: Encodable {
    let did: String
    let canonicalHandle: String
    let status: String
    let publicGenesisCommitCID: String
    let publicGenesisRevision: String
    let recovered: Bool

    init(installation: LocalAccountInstallation) {
        did = installation.account.did
        canonicalHandle = installation.account.canonicalHandle
        status = installation.account.status.rawValue
        publicGenesisCommitCID = installation.publicGenesis.genesis.commitCID.string
        publicGenesisRevision = installation.publicGenesis.genesis.revision
        recovered = installation.registrationWasRecovered
    }
}

private struct PreparedPLCAccountIdentityView: Encodable {
    let requestID: String
    let did: String
    let canonicalHandle: String
    let pdsOrigin: String
    let repositoryRevision: String
    let plcOperationCID: String
    let publicGenesisCommitCID: String

    init(identity: PreparedPLCAccountIdentity) {
        requestID = identity.requestID
        did = identity.did
        canonicalHandle = identity.canonicalHandle
        pdsOrigin = identity.pdsOrigin
        repositoryRevision = identity.repositoryRevision
        plcOperationCID = identity.plcOperationCID
        publicGenesisCommitCID = identity.publicGenesisCommitCID
    }

    init(result: SwanManagementPLCPrepareResult) {
        requestID = result.requestId
        did = result.did
        canonicalHandle = result.canonicalHandle
        pdsOrigin = result.pdsOrigin
        repositoryRevision = result.repositoryRevision
        plcOperationCID = result.plcOperationCID
        publicGenesisCommitCID = result.publicGenesisCommitCID
    }
}

private struct RotatedPLCAccountView: Encodable {
    let did: String
    let status: String
    let generation: UInt64
    let operationCID: String
    let previousOperationCID: String?

    init(result: RotatedPLCAccountIdentity) throws {
        did = result.account.did
        status = result.account.status.rawValue
        generation = result.generation
        operationCID = try result.operation.cid.string
        previousOperationCID = result.operation.prev
    }
}

private func makePermanentDeletionPLCConfiguration(
    origin: String?,
    laboratory: Bool,
    laboratoryAllowlistedHost: String?,
    referenceCompatibility: String?
) throws -> PLCClientConfiguration {
    let rawOrigin =
        origin ?? PLCClientConfiguration.defaultProductionOrigin.absoluteString
    guard let directoryOrigin = URL(string: rawOrigin) else {
        throw ValidationError("permanent-deletion PLC origin must be a URL")
    }
    let responsePolicy: PLCSubmitSuccessResponsePolicy
    switch referenceCompatibility {
    case nil:
        responsePolicy = .strict
    case PLCSubmitSuccessResponsePolicy.didPLCServer001.rawValue:
        guard laboratory else {
            throw ValidationError(
                "permanent-deletion PLC reference compatibility requires laboratory mode"
            )
        }
        responsePolicy = .didPLCServer001
    case .some:
        throw ValidationError(
            "permanent-deletion PLC reference compatibility is unsupported"
        )
    }
    do {
        if laboratory {
            return try .laboratory(
                origin: directoryOrigin,
                submitSuccessResponsePolicy: responsePolicy,
                allowlistedHost: laboratoryAllowlistedHost
            )
        }
        guard laboratoryAllowlistedHost == nil else {
            throw ValidationError(
                "permanent-deletion PLC laboratory allowlist requires laboratory mode"
            )
        }
        return try .production(origin: directoryOrigin)
    } catch let error as ValidationError {
        throw error
    } catch {
        throw ValidationError(
            "permanent-deletion PLC configuration is invalid"
        )
    }
}

enum AccountCommandSupport {
    static func authorization(secretFilePath: String?) throws -> AccountOperatorAuthorization {
        do {
            return try OperatorSecretResolver.authorize(
                secretFile: secretFilePath.map { URL(fileURLWithPath: $0) }
            )
        } catch {
            throw validationError(for: error)
        }
    }

    static func withService(
        dataDirectory: String,
        operation: (AccountOperatorService) async throws -> AccountOperatorView
    ) async throws -> AccountOperatorView {
        guard !dataDirectory.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ValidationError("--data-directory must not be empty")
        }
        let control: SQLiteControlDatabase
        do {
            control = try await SQLiteControlDatabase(
                dataDirectory: URL(fileURLWithPath: dataDirectory)
            )
        } catch {
            throw ValidationError("unable to open Swan control database")
        }
        do {
            let view = try await operation(AccountOperatorService(store: control))
            try await control.close()
            return view
        } catch {
            try? await control.close()
            throw validationError(for: error)
        }
    }

    static func write(_ view: some Encodable) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(view)
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }

    static func write(_ view: AccountOperatorView) throws {
        let data = try AccountOperatorJSON.render(view)
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }

    static func validationError(for error: any Error) -> ValidationError {
        if let error = error as? AccountOperatorError,
           let message = error.errorDescription {
            return ValidationError(message)
        }
        if let error = error as? SwanError {
            return ValidationError(error.description)
        }
        return ValidationError("account operation failed")
    }
}

private struct SingleAccountFirehoseSource: PublicFirehoseAccountDatabaseSource {
    let account: PublicFirehoseAccountDatabase

    func publicFirehoseAccountDatabases() async throws -> [PublicFirehoseAccountDatabase] {
        [account]
    }
}
