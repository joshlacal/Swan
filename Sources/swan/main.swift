import ArgumentParser
import Crypto
import Foundation
import Logging
import SwanAccountExport
import SwanAccounts
import SwanHTTP
import SwanInterop
import SwanCore
import SwanOAuth
import SwanPublicRepository
import SwanSQLite
import SwanStorage
import ServiceLifecycle

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
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

    static func load(from url: URL) throws -> ServeNotificationRuntime {
        let data: Data
        do {
            data = try Data(contentsOf: url, options: [.mappedIfSafe])
        } catch {
            throw ValidationError("--notification-config is unavailable")
        }
        guard data.count > 0, data.count <= 256 * 1_024 else {
            throw ValidationError("--notification-config has invalid size")
        }
        let configuration: Configuration
        do {
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
                keyID: pin.keyID ?? PermissionedDataJWT.spaceCredentialKeyID,
                generation: pin.generation,
                publicKey: P256.Signing.PublicKey(x963Representation: bytes.value)
            )
        case .es256k:
            return try .init(
                authority: pin.issuer,
                keyID: pin.keyID ?? PermissionedDataJWT.spaceCredentialKeyID,
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
        guard let account = try await controls.account(did: selector),
              let store = await directory.preopenedPublicMutationStore(did: selector) else { return nil }
        return try PublicRepositoryMutationTarget(did: account.did, status: account.status, store: store)
    }

    func publicBlob(cid: String) async throws -> PublicBlob? {
        for did in try await controls.activeAccountDIDs() {
            guard let store = await directory.preopenedPublicMutationStore(did: did),
                  let blobs = store as? any StreamingBlobStore else { continue }
            if let blob = try await blobs.publicBlob(cid: cid) { return blob }
        }
        return nil
    }
}

private struct ServePublicMutationSignerProvider: PublicRepositoryMutationSignerProvider {
    let accounts: DurableAccountDirectory
    let keyStore: any AccountKeyStore

    func signer(for did: String) async throws -> any PublicRepositoryCommitSigner {
        guard let account = try await accounts.account(did: did), account.status.authorizesAccount,
              let references = try await accounts.keyReferences(did: did) else {
            throw SwanError.unauthorized("public repository signer is unavailable")
        }
        let material = try await keyStore.key(for: references.signing)
        return P256PublicRepositoryCommitSigner(privateKey: try P256.Signing.PrivateKey(rawRepresentation: material))
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
    let credentialSigningKeys: any SpaceCredentialSigningKeyResolver
    let credentialPublicKeys: any SpaceCredentialPublicKeyResolver
    let delegationPublicKeys: any SpaceDelegationPublicKeyResolver
    let servicePublicKeys: any SpaceServicePublicKeyResolver
    let credentialExchangeConfiguration: SwanSpaceCredentialHTTPConfiguration
    let delegationConfiguration: SwanSpaceDelegationHTTPConfiguration
    let repositorySyncConfiguration: SwanSpaceRepositorySyncHTTPConfiguration
    let repositoryCredentialConfiguration: SwanSpaceCredentialVerificationHTTPConfiguration
    let notificationServiceIssuer: any SpaceServiceAuthenticationIssuer
    let publicMutationSignerProvider: any PublicRepositoryMutationSignerProvider

    static func make(
        keyDirectory: URL,
        kekFile: URL,
        kekID: String,
        controlStore: SQLiteControlDatabase
    ) async throws -> ServeLocalSpaceRuntime {
        // `FileAccountKeyStore` will repeat this check while opening its
        // descriptor.  Keep this preflight non-creating: `serve` must not
        // create a key directory merely because local interop was requested.
        try requireExistingOwnerOnlyKeyDirectory(keyDirectory)
        let configuration = try AccountProvisioningSecrets
            .requiredMountedAccountKeyConfiguration(
                activeKeyID: kekID,
                secretFile: kekFile
            )
        let keyStore = try FileAccountKeyStore(
            root: keyDirectory,
            configuration: configuration
        )
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
        let publicMutationSignerProvider = ServePublicMutationSignerProvider(
            accounts: accounts, keyStore: keyStore
        )

        return .init(
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
            notificationServiceIssuer: notificationServiceIssuer,
            publicMutationSignerProvider: publicMutationSignerProvider
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
    let checkUserAccessConfiguration: SwanSimpleSpaceCheckUserAccessHTTPConfiguration?

    static func compose(
        local: ServeLocalSpaceRuntime?,
        notification: ServeNotificationRuntime?,
        clientAttestationPolicy: any SpaceCredentialClientAttestationPolicy =
            UnavailableSpaceCredentialClientAttestationPolicy()
    ) async throws -> ServePermissionedRuntime {
        let credentialPublicKeys: (any SpaceCredentialPublicKeyResolver)?
        let delegationPublicKeys: (any SpaceDelegationPublicKeyResolver)?
        let servicePublicKeys: (any SpaceServicePublicKeyResolver)?

        switch (local, notification) {
        case let (.some(local), .some(notification)):
            credentialPublicKeys = try await CompositeSpaceCredentialPublicKeyResolver(
                local: local.credentialPublicKeys,
                pinned: notification.credentialPins
            )
            delegationPublicKeys = try await CompositeSpaceDelegationPublicKeyResolver(
                local: local.delegationPublicKeys,
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
            credentialPublicKeys = notification.credentialPublicKeys
            delegationPublicKeys = notification.delegationPublicKeys
            servicePublicKeys = notification.servicePublicKeys
        case (nil, nil):
            credentialPublicKeys = nil
            delegationPublicKeys = nil
            servicePublicKeys = nil
        }

        let credentialConfiguration: SwanSpaceCredentialHTTPConfiguration?
        if let credentialPublicKeys, let delegationPublicKeys {
            credentialConfiguration = .init(
                authoritySigningKeys: local?.credentialSigningKeys
                    ?? ServeUnavailableCredentialSigningKeyResolver(),
                delegationPublicKeys: delegationPublicKeys,
                credentialPublicKeys: credentialPublicKeys
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
                recipientBindings: notification?.recipientBindings ?? .empty
            )
        } else {
            serviceAuthentication = nil
            notificationConfiguration = nil
        }

        let checkUserAccessConfiguration: SwanSimpleSpaceCheckUserAccessHTTPConfiguration?
        if let serviceAuthentication,
           let managingServiceAudience = notification?.managingServiceAudience {
            checkUserAccessConfiguration = try .init(
                serviceAuthentication: serviceAuthentication,
                managingServiceAudience: managingServiceAudience
            )
        } else {
            checkUserAccessConfiguration = nil
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
                    clientAttestationPolicy: clientAttestationPolicy
                )
            },
            delegationConfiguration: local?.delegationConfiguration,
            repositorySyncConfiguration: local?.repositorySyncConfiguration,
            repositoryCredentialConfiguration: credentialPublicKeys.map {
                .init(credentialPublicKeys: $0)
            },
            notificationConfiguration: notificationConfiguration,
            checkUserAccessConfiguration: checkUserAccessConfiguration
        )
    }

    func makeServer(
        profile: ProtocolProfile,
        configuration: SwanHTTPConfiguration,
        oauthRuntime: SwanOAuthRuntime,
        directory: SQLitePreMigratedAccountDirectory,
        accountControlStore: SQLiteControlDatabase,
        localSpaceRuntime: ServeLocalSpaceRuntime? = nil,
        localhostPARConfiguration: SwanLocalhostPARConfiguration? = nil,
        localhostOAuthConfiguration: SwanLocalhostOAuthConfiguration? = nil,
        authorizationServerConfiguration: SwanOAuthAuthorizationServerConfiguration? = nil
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
            simpleSpaceCheckUserAccessConfiguration: checkUserAccessConfiguration,
            publicRepositoryReadDirectory: directory,
            publicRepositoryMutationDirectory: localSpaceRuntime.map { _ in ServePublicMutationDirectory(directory: directory, controls: accountControlStore) },
            publicRepositoryMutationSignerProvider: localSpaceRuntime?.publicMutationSignerProvider
        )
    }
}

/// The key store itself repeats this descriptor-safe validation when it opens
/// the directory. This check exists solely to prohibit `serve` from creating a
/// new key root in its opt-in runtime path.
private func requireExistingOwnerOnlyKeyDirectory(_ url: URL) throws {
    let descriptor = url.withUnsafeFileSystemRepresentation { path in
        guard let path else { return Int32(-1) }
        return open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard descriptor >= 0 else {
        throw SwanError.unavailable("local space key directory is unavailable")
    }
    defer { _ = close(descriptor) }
    var status = stat()
    guard fstat(descriptor, &status) == 0,
          (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR),
          status.st_uid == geteuid(),
          Int(status.st_mode & mode_t(0o777)) == 0o700 else {
        throw SwanError.unavailable("local space key directory is unavailable")
    }
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

private func readOAuthServerKeyFile(_ url: URL) throws -> Data {
    let descriptor: Int32 = url.withUnsafeFileSystemRepresentation { path in
        guard let path else { return Int32(-1) }
        return open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    }
    guard descriptor >= 0 else { throw ValidationError("oauth-server-key file is unavailable") }
    defer { _ = close(descriptor) }

    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
          (metadata.st_mode & S_IFMT) == S_IFREG,
          metadata.st_uid == geteuid(),
          (metadata.st_mode & (S_IRWXG | S_IRWXO)) == 0,
          metadata.st_size > 0,
          metadata.st_size <= off_t(256) else {
        throw ValidationError("oauth-server-key file is unavailable")
    }

    do {
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        let raw = try handle.read(upToCount: 259) ?? Data()
        guard raw.count <= 258 else {
            throw ValidationError("oauth-server-key file is invalid")
        }
        return try decodeBase64URLOAuthServerKey(raw)
    } catch let error as ValidationError {
        throw error
    } catch {
        throw ValidationError("oauth-server-key is unavailable")
    }
}

@main
struct SwanCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "swan",
        abstract: "Swift-native AT Protocol permissioned-data interoperability laboratory",
        subcommands: [
            Serve.self, Account.self, Export.self, Backup.self, Restore.self, Verify.self, Lab.self,
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
                let result = try SwanPortableAccountRestoreStager().stage(
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
                keyConfiguration = try AccountProvisioningSecrets.accountKeyConfiguration(
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
        var profile: String = "Profiles/permissioned-data-0016-2026-07-03.json"

        @Option(name: .long)
        var host: String = "127.0.0.1"

        @Option(name: .long)
        var port: Int = 3000

        @Option(name: .long, help: "Public issuer URL")
        var publicURL: String?

        @Flag(name: .long, help: "Enable only the localhost-development-client OAuth PAR bridge; requires an HTTPS public issuer")
        var enableLocalhostPAR = false

        @Flag(name: .customLong("enable-localhost-oauth"), help: "Enable the localhost-development-client PAR, browser authorization, token, refresh, and revocation bridge; requires an HTTPS public issuer")
        var enableLocalhostOAuth = false

        @Flag(name: .customLong("enable-oauth-authorization-server"), help: "Enable the complete remote/public and private_key_jwt OAuth authorization server; requires an HTTPS public issuer and durable account/password support")
        var enableOAuthAuthorizationServer = false

        @Flag(name: .customLong("oauth-allow-localhost-development-client"), help: "Permit only AT Protocol's exact http://localhost development client metadata exception in the complete OAuth server")
        var oauthAllowLocalhostDevelopmentClient = false

        @Option(
            name: .customLong("oauth-server-key-file"),
            help: "Owner-only mounted file containing the URL-safe-base64 OAuth server key; SWAN_OAUTH_SERVER_KEY is the legacy alternative"
        )
        var oauthServerKeyFile: String?

        @Option(name: .customLong("oauth-allow-metadata-ip"), help: "Explicit literal IP allowlist for laboratory OAuth client metadata/JWKS retrieval; repeat for each address")
        var oauthMetadataAllowedIPs: [String] = []

        @Option(name: .long, help: "Reserved root for control/account databases and blobs")
        var dataDirectory: String = ".swan-data"

        @Option(name: .long, help: "Enable the separate loopback-only management listener on this port")
        var managementPort: Int?

        @Option(name: .long, help: "Literal loopback address for management: 127.0.0.1 or ::1")
        var managementAddress: String = "127.0.0.1"

        @Option(name: .long, help: "Mounted operator-secret file for the enabled management listener")
        var managementOperatorSecretFile: String?

        @Flag(name: .customLong("enable-management-plc-provisioning"), help: "Enable authenticated PLC prepare/activate routes on the separate management listener")
        var enableManagementPLCProvisioning = false

        @Option(name: .customLong("management-account-kek-file"), help: "Owner-only mounted account-KEK file for management PLC provisioning; SWAN_ACCOUNT_KEK is the alternative")
        var managementAccountKEKFile: String?

        @Option(name: .customLong("management-account-kek-id"), help: "Active account-KEK identifier for management PLC provisioning")
        var managementAccountKEKID: String?

        @Option(name: .customLong("management-account-key-directory"), help: "Protected account key-envelope directory for management PLC provisioning; defaults to <data-directory>/keys")
        var managementAccountKeyDirectory: String?

        @Option(name: .customLong("notification-config"), help: "Owner-supplied JSON with ES256/ES256K public pins, peer-pinned destinations, and receiver service-identity bindings")
        var notificationConfig: String?

        @Flag(name: .customLong("enable-notification-delivery"), help: "Enable durable peer-pinned writer notifications and deletion recovery delivery")
        var enableNotificationDelivery = false

        @Option(name: .customLong("notification-account-kek-file"), help: "Owner-only mounted account-KEK file for notification signing; SWAN_ACCOUNT_KEK is the alternative")
        var notificationAccountKEKFile: String?

        @Option(name: .customLong("notification-account-kek-id"), help: "Active account-KEK identifier for notification signing (default: primary)")
        var notificationAccountKEKID: String?

        @Option(name: .customLong("notification-account-key-directory"), help: "Protected account key-envelope directory for notification signing; defaults to <data-directory>/keys")
        var notificationAccountKeyDirectory: String?

        @Flag(
            name: .customLong("enable-local-space-interop"),
            help: "Enable local account-key credential, delegation, and repository-sync interop."
        )
        var enableLocalSpaceInterop = false

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

        func run() async throws {
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
            guard !enableManagementPLCProvisioning || managementPort != nil else {
                throw ValidationError("--enable-management-plc-provisioning requires --management-port")
            }
            if !enableManagementPLCProvisioning {
                guard managementAccountKEKFile == nil,
                      managementAccountKeyDirectory == nil,
                      managementAccountKEKID == nil
                else {
                    throw ValidationError("management account KEK options require --enable-management-plc-provisioning")
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
            let loadedProfile = try ProtocolProfile.load(from: URL(fileURLWithPath: profile))
            let baseURL = try publicURL.map { value in
                guard let url = URL(string: value) else { throw ValidationError("--public-url must be a URL") }
                return url
            } ?? URL(string: "http://\(host):\(port)")!
            if enableLocalSpaceInterop,
               baseURL.scheme?.lowercased() != "https" {
                throw ValidationError(
                    "--enable-local-space-interop requires an HTTPS --public-url"
                )
            }
            let dataURL = URL(fileURLWithPath: dataDirectory)
            let serverKey = try loadOAuthServerKey(fromFile: oauthServerKeyFile)
            let controlDatabase = try await SQLiteControlDatabase(dataDirectory: dataURL)
            var preopenedAccountDirectory: SQLitePreMigratedAccountDirectory?
            var preopenedManagementProvisioning: SwanManagementPLCProvisioningRuntime?
            do {
                // Permissioned lookup never creates or migrates an account
                // database during a request. Build the complete active set
                // before the public listener exists; failures keep the
                // endpoint unavailable rather than repairing state online.
                let directory = try await SQLitePreMigratedAccountDirectory.bootstrap(
                    dataDirectory: dataURL,
                    controlStore: controlDatabase,
                    publicIdentityVerifier: SwanPublicPLCGenesisVerifier()
                )
                preopenedAccountDirectory = directory
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
                let oauthRuntime = try SwanOAuthRuntime(
                    controlStore: controlDatabase,
                    serverKey: serverKey
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
                let localhostOAuthConfiguration: SwanLocalhostOAuthConfiguration?
                if enableLocalhostOAuth {
                    do {
                        let passwordHasher = try LibsodiumArgon2idHasher()
                        let accounts = DurableAccountDirectory(
                            store: controlDatabase,
                            passwordHasher: passwordHasher,
                            verificationExecutor: try Argon2idVerificationExecutor(hasher: passwordHasher)
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
                let authorizationServerConfiguration: SwanOAuthAuthorizationServerConfiguration?
                if enableOAuthAuthorizationServer {
                    do {
                        guard let clientMetadataLoader else {
                            throw SwanError.unavailable(
                                "OAuth client metadata loader is unavailable"
                            )
                        }
                        let passwordHasher = try LibsodiumArgon2idHasher()
                        let accounts = DurableAccountDirectory(
                            store: controlDatabase,
                            passwordHasher: passwordHasher,
                            verificationExecutor: try Argon2idVerificationExecutor(hasher: passwordHasher)
                        )
                        authorizationServerConfiguration = try SwanOAuthAuthorizationServerConfiguration(
                            issuer: baseURL,
                            protectedResource: baseURL,
                            accounts: accounts,
                            clientMetadataLoader: clientMetadataLoader
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
                if let notificationConfig {
                    notificationRuntime = try ServeNotificationRuntime.load(
                        from: URL(fileURLWithPath: notificationConfig)
                    )
                } else {
                    notificationRuntime = nil
                }
                guard !enableNotificationDelivery || notificationRuntime != nil else {
                    throw ValidationError("--enable-notification-delivery requires --notification-config")
                }
                let permissionedRuntime: ServePermissionedRuntime
                do {
                    permissionedRuntime = try await .compose(
                        local: localSpaceRuntime,
                        notification: notificationRuntime,
                        clientAttestationPolicy: clientAttestationPolicy
                    )
                } catch {
                    throw ValidationError("permissioned runtime key composition is invalid")
                }
                let notificationRecoveryService: SwanNotificationRecoveryService?
                if enableNotificationDelivery, let notificationRuntime {
                    guard !notificationRuntime.peerPinnedTransportConfiguration.endpointPeers.isEmpty else {
                        throw ValidationError("--enable-notification-delivery requires at least one peer-pinned destination")
                    }
                    let serviceIssuer: any SpaceServiceAuthenticationIssuer
                    if let localSpaceRuntime,
                       notificationAccountKEKFile == nil,
                       notificationAccountKEKID == nil,
                       notificationAccountKeyDirectory == nil {
                        serviceIssuer = localSpaceRuntime.notificationServiceIssuer
                    } else {
                        let keyStore: FileAccountKeyStore
                        do {
                            let keyConfiguration = try AccountProvisioningSecrets.accountKeyConfiguration(
                                activeKeyID: notificationAccountKEKID ?? "primary",
                                secretFile: notificationAccountKEKFile.map { URL(fileURLWithPath: $0) }
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
                    let poster: OAuthBoundedJSONPoster
                    do {
                        poster = .init(
                            policy: try OAuthRemoteFetchPolicy(allowLocalhostDevelopment: true),
                            transport: NIOPeerPinnedOAuthPostTransport(
                                configuration: notificationRuntime.peerPinnedTransportConfiguration
                            )
                        )
                    } catch {
                        throw ValidationError("notification peer-pinned transport is unavailable")
                    }
                    notificationRecoveryService = try await .fromPreopenedDirectory(
                        directory,
                        makeOutboxTransport: { database in
                            HTTPPermissionedSpaceOutboxTransport(
                                destinations: notificationRuntime.destinations,
                                announcements: .init(database: database),
                                serviceAuthentication: serviceIssuer,
                                poster: poster
                            )
                        },
                        makeFanoutTransport: { database in
                            HTTPPermissionedSpaceNotificationFanoutTransport(
                                database: database,
                                destinations: notificationRuntime.destinations,
                                serviceAuthentication: serviceIssuer,
                                poster: poster
                            )
                        }
                    )
                } else {
                    notificationRecoveryService = nil
                }
                let managementPLCProvisioning: SwanManagementPLCProvisioningRuntime?
                if enableManagementPLCProvisioning {
                    do {
                        let keyConfiguration = try AccountProvisioningSecrets.accountKeyConfiguration(
                            activeKeyID: managementAccountKEKID ?? "primary",
                            secretFile: managementAccountKEKFile.map { URL(fileURLWithPath: $0) }
                        )
                        let keyDirectory = managementAccountKeyDirectory.map {
                            URL(fileURLWithPath: $0)
                        } ?? dataURL.appending(path: "keys")
                        let keyStore = try FileAccountKeyStore(
                            root: keyDirectory,
                            configuration: keyConfiguration
                        )
                        managementPLCProvisioning = try .init(
                            controlDatabase: controlDatabase,
                            dataDirectory: dataURL,
                            keyStore: keyStore,
                            liveAccountDirectory: directory
                        )
                        preopenedManagementProvisioning = managementPLCProvisioning
                    } catch {
                        throw ValidationError("management PLC provisioning runtime is unavailable")
                    }
                } else {
                    managementPLCProvisioning = nil
                }
                let server = permissionedRuntime.makeServer(
                    profile: loadedProfile,
                    configuration: .init(host: host, port: port, publicURL: baseURL),
                    oauthRuntime: oauthRuntime,
                    directory: directory,
                    accountControlStore: controlDatabase,
                    localSpaceRuntime: localSpaceRuntime,
                    localhostPARConfiguration: localhostPARConfiguration,
                    localhostOAuthConfiguration: localhostOAuthConfiguration,
                    authorizationServerConfiguration: authorizationServerConfiguration
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
                let managementApplication: (any Service)?
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
                    let managementServer = SwanManagementHTTPServer(
                        configuration: managementConfiguration,
                        controlStore: controlDatabase,
                        operatorSecretVerifier: verifier,
                        plcProvisioning: managementPLCProvisioning
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
                logger.info("starting Swan", metadata: ["profile": .string(loadedProfile.id), "address": .string("\(host):\(port)")])
                var services: [any Service] = [publicApplication]
                if permissionedRuntime.notificationConfiguration != nil {
                    logger.info("space notification receiver routes enabled")
                }
                if let notificationRecoveryService {
                    services.append(notificationRecoveryService)
                    logger.info("space notification recovery delivery enabled with peer-pinned NIO transport")
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
                try await directory.close()
                try await controlDatabase.close()
            } catch {
                if let preopenedManagementProvisioning {
                    try? await preopenedManagementProvisioning.close()
                }
                if let preopenedAccountDirectory {
                    try? await preopenedAccountDirectory.close()
                }
                try? await controlDatabase.close()
                throw error
            }
        }

        private func loadOAuthServerKey(fromFile path: String?) throws -> Data {
            let trimmedPath = path?.trimmingCharacters(in: .whitespacesAndNewlines)
            let encoded = ProcessInfo.processInfo.environment["SWAN_OAUTH_SERVER_KEY"]
            if trimmedPath != nil && encoded != nil {
                throw ValidationError(
                    "oauth-server-key source is ambiguous; use either --oauth-server-key-file or SWAN_OAUTH_SERVER_KEY"
                )
            }
            if let keyFilePath = trimmedPath {
                guard !keyFilePath.isEmpty else {
                    throw ValidationError("oauth-server-key-file must not be empty")
                }
                return try readOAuthServerKeyFile(URL(fileURLWithPath: keyFilePath))
            }
            guard let encoded,
                  let key = Data(base64URLEncoded: encoded),
                  key.count == 32 else {
                throw ValidationError(
                    "SWAN_OAUTH_SERVER_KEY must contain a URL-safe-base64 32-byte server key"
                )
            }
            return key
        }
    }

    struct Verify: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Verify a pinned Swan artifact")

        @Option(name: .long, help: "Pinned protocol profile JSON")
        var profile: String = "Profiles/permissioned-data-0016-2026-07-03.json"

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
                InstallLocal.self, PreparePLC.self, ActivatePLC.self, Show.self,
                Deactivate.self, Reactivate.self, DeclareExport.self, Delete.self,
            ]
        )

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

            @Option(name: .long, help: "Owner-only mounted account-KEK file (URL-safe base64); SWAN_ACCOUNT_KEK is the alternative")
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
                let keyConfiguration = try AccountProvisioningSecrets.accountKeyConfiguration(
                    activeKeyID: accountKEKID,
                    secretFile: accountKEKFile.map { URL(fileURLWithPath: $0) }
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

            @Option(name: .long, help: "PLC directory origin")
            var plcOrigin: String = PLCClientConfiguration.defaultProductionOrigin.absoluteString

            @Flag(name: .long, help: "Select explicit literal-loopback HTTP PLC laboratory policy")
            var plcLaboratory = false

            @Option(name: .long, help: "Pinned PLC submit compatibility; only did-plc-server-0.0.1 is supported")
            var plcReferenceCompatibility: String?

            @Option(name: .long, help: "Mounted operator-secret file; never accepted as a literal argument")
            var operatorSecretFile: String?

            @Option(name: .long, help: "Owner-only mounted account-KEK file (URL-safe base64); SWAN_ACCOUNT_KEK is the alternative")
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
                            submitSuccessResponsePolicy: responsePolicy
                        )
                    } else {
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

                let keyConfiguration: AccountKeyEncryptionConfiguration
                do {
                    keyConfiguration = try AccountProvisioningSecrets.accountKeyConfiguration(
                        activeKeyID: accountKEKID,
                        secretFile: accountKEKFile.map { URL(fileURLWithPath: $0) }
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
                name: .long,
                help: "Literal-loopback HTTP origin for laboratory /.well-known/atproto-did proof"
            )
            var handleLaboratoryOrigin: String?

            @Option(name: .long, help: "Mounted operator-secret file; never accepted as a literal argument")
            var operatorSecretFile: String?

            @Option(name: .long, help: "Owner-only mounted account-KEK file (URL-safe base64); SWAN_ACCOUNT_KEK is the alternative")
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
                        guard let rawHandleOrigin = handleLaboratoryOrigin,
                              let handleOrigin = URL(string: rawHandleOrigin) else {
                            throw SwanError.malformed(
                                "--handle-laboratory-origin is required with --plc-laboratory"
                            )
                        }
                        plcConfiguration = try .laboratory(origin: directoryOrigin)
                        handlePolicy = try .laboratory(origin: handleOrigin)
                    } else {
                        guard handleLaboratoryOrigin == nil else {
                            throw SwanError.malformed(
                                "--handle-laboratory-origin requires --plc-laboratory"
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
                    keyConfiguration = try AccountProvisioningSecrets.accountKeyConfiguration(
                        activeKeyID: accountKEKID,
                        secretFile: accountKEKFile.map { URL(fileURLWithPath: $0) }
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
                        handlePolicy: preparedConfiguration.handle
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

            func run() async throws {
                let authorization = try AccountCommandSupport.authorization(
                    secretFilePath: operatorSecretFile
                )
                let view = try await AccountCommandSupport.withService(
                    dataDirectory: dataDirectory
                ) { service in
                    try await service.delete(
                        did: did,
                        tombstoneReason: tombstoneReason,
                        exportReference: exportReference,
                        authorization: authorization
                    )
                }
                try AccountCommandSupport.write(view)
            }
        }
    }

    struct Lab: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Validate and record sanitized Compose laboratory scenarios",
            subcommands: [Validate.self, Matrix.self, Scenario.self],
            defaultSubcommand: Validate.self
        )

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

            @Flag(name: .long, help: "Return non-zero when scenario status is not passed")
            var failOnFailure: Bool = false

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

            @Flag(name: .long, help: "Return non-zero when any matrix cell is not passed")
            var failOnFailure: Bool = false

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

private enum AccountCommandSupport {
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
