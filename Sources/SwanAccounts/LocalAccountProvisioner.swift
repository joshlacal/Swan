import Crypto
import Foundation
import SwanCore
import SwanPublicRepository
import SwanStorage

/// Successful local installation binds one active control-plane account to a
/// previously verified, immutable public empty-repository genesis. It contains
/// no password verifier or private key material.
public struct LocalAccountInstallation: Sendable, Equatable {
    public let account: AccountControlAccount
    public let publicGenesis: PersistedPublicRepositoryGenesis
    public let registrationWasRecovered: Bool

    public init(
        account: AccountControlAccount,
        publicGenesis: PersistedPublicRepositoryGenesis,
        registrationWasRecovered: Bool
    ) {
        self.account = account
        self.publicGenesis = publicGenesis
        self.registrationWasRecovered = registrationWasRecovered
    }
}

/// Recovery reconciliation intentionally exposes only two broad outcomes.
/// In particular, a wrong password, stale lifecycle state, and mismatched key
/// references do not reveal which pre-existing control fact caused a retry to
/// fail.
public enum LocalAccountProvisioningError: Error, Sendable, Equatable {
    case conflict
    case unavailable
}

/// Internal-only seam for the crash-recovery test. It runs after the public
/// genesis transaction committed and before any attempt to create an active
/// control-plane row. Production construction always supplies no hook.
struct LocalAccountProvisioningHooks: Sendable {
    var afterPublicGenesisInstalled: (@Sendable () async throws -> Void)?
}

/// Coordinates the small local PDS installation sequence without pretending
/// that the per-account repository and `control.sqlite` share a transaction.
/// The ordering is deliberate: an observer may see a valid unregistered
/// genesis after a crash, but it can never see an active account created by
/// this service without that genesis already being durable.
public actor LocalAccountProvisioner {
    private let directory: DurableAccountDirectory
    private let publicGenesisStore: any PublicRepositoryGenesisStore
    private let keyProvisioner: AccountKeyProvisioner
    private let keyStore: any AccountKeyStore
    private let testingHooks: LocalAccountProvisioningHooks

    public init(
        directory: DurableAccountDirectory,
        publicGenesisStore: any PublicRepositoryGenesisStore,
        keyProvisioner: AccountKeyProvisioner,
        keyStore: any AccountKeyStore
    ) {
        self.directory = directory
        self.publicGenesisStore = publicGenesisStore
        self.keyProvisioner = keyProvisioner
        self.keyStore = keyStore
        testingHooks = .init()
    }

    init(
        directory: DurableAccountDirectory,
        publicGenesisStore: any PublicRepositoryGenesisStore,
        keyProvisioner: AccountKeyProvisioner,
        keyStore: any AccountKeyStore,
        testingHooks: LocalAccountProvisioningHooks
    ) {
        self.directory = directory
        self.publicGenesisStore = publicGenesisStore
        self.keyProvisioner = keyProvisioner
        self.keyStore = keyStore
        self.testingHooks = testingHooks
    }

    /// Creates or resumes the local half of a provisioned account. PLC
    /// registration, remote handle verification, HTTP provisioning, and DID
    /// lifecycle updates are intentionally outside this narrow workflow.
    public func install(
        did rawDID: String,
        handle rawHandle: String,
        password: String,
        revision: String,
        now: Date = Date()
    ) async throws -> LocalAccountInstallation {
        let did = try AccountIdentifiers.validateDID(rawDID)
        let handle = try AccountIdentifiers.canonicalHandle(rawHandle)
        try PublicRepositoryGenesisCodec.validateRevision(revision)

        // `provisionInitial` is create-only but resumes the exact generation
        // one pair after an interrupted run, so a retry never silently rolls
        // the account signing key forward.
        let keys = try await keyProvisioner.provisionInitial(accountDID: did)
        let signingKey = try await loadSigningKey(for: keys.signingReference)
        let existingControl = try await existingControlAccount(did: did)
        let installation = try await installOrLoadPublicGenesis(
            did: did,
            revision: revision,
            signingKey: signingKey,
            hasExistingControl: existingControl != nil,
            now: now
        )

        try await testingHooks.afterPublicGenesisInstalled?()

        do {
            // The immutable genesis commit CID, rather than a coincidental
            // timestamp, binds this control registration to the verified
            // public genesis. Preserve the caller's account-creation time.
            let account = try await directory.registerProvisionedAccount(
                did: did,
                canonicalHandle: handle,
                password: password,
                signingReference: keys.signingReference,
                rotationReference: keys.rotationReference,
                publicGenesisCommitCID: installation.persisted.genesis.commitCID.string,
                now: now
            )
            return LocalAccountInstallation(
                account: account,
                publicGenesis: installation.persisted,
                registrationWasRecovered: installation.wasAlreadyInstalled
            )
        } catch let error as AccountControlStoreError {
            switch error {
            case .duplicateDID, .duplicateHandle:
                let account = try await reconcileDuplicateRegistration(
                    did: did,
                    handle: handle,
                    password: password,
                    signingReference: keys.signingReference,
                    rotationReference: keys.rotationReference,
                    publicGenesis: installation.persisted
                )
                return LocalAccountInstallation(
                    account: account,
                    publicGenesis: installation.persisted,
                    registrationWasRecovered: true
                )
            case .unavailable:
                throw LocalAccountProvisioningError.unavailable
            case .notFound, .invalidInput, .invalidStatus, .invalidTransition,
                    .malformedRecord:
                throw LocalAccountProvisioningError.unavailable
            }
        }
    }

    private func loadSigningKey(
        for reference: AccountKeyReference
    ) async throws -> P256.Signing.PrivateKey {
        do {
            let material = try await keyStore.key(for: reference)
            return try P256.Signing.PrivateKey(rawRepresentation: material)
        } catch {
            throw LocalAccountProvisioningError.unavailable
        }
    }

    private func installOrLoadPublicGenesis(
        did: String,
        revision: String,
        signingKey: P256.Signing.PrivateKey,
        hasExistingControl: Bool,
        now: Date
    ) async throws -> PublicRepositoryGenesisInstallation {
        if let existing = try await publicGenesisStore.loadPublicRepositoryGenesis(
            did: did,
            signingPublicKey: signingKey.publicKey
        ) {
            guard existing.genesis.revision == revision else {
                throw LocalAccountProvisioningError.conflict
            }
            return PublicRepositoryGenesisInstallation(
                persisted: existing,
                wasAlreadyInstalled: true
            )
        }
        // This workflow always writes genesis first. A control row that was
        // present before an absent genesis is either legacy or corrupt; do
        // not manufacture public state which a later duplicate path could
        // mistake for local-install provenance.
        guard !hasExistingControl else {
            throw LocalAccountProvisioningError.conflict
        }

        let candidate = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: revision,
            signingKey: signingKey
        )
        do {
            return try await publicGenesisStore.installPublicRepositoryGenesis(
                candidate,
                signingPublicKey: signingKey.publicKey,
                installedAt: now
            )
        } catch let error as PublicRepositoryGenesisStoreError where error == .conflictingGenesis {
            // A separate first writer can commit an equivalent signed genesis
            // after our load but before this insert. ECDSA signatures are
            // intentionally fresh, so use the already persisted CAR rather
            // than manufacturing a second valid but divergent envelope.
            guard let existing = try await publicGenesisStore.loadPublicRepositoryGenesis(
                did: did,
                signingPublicKey: signingKey.publicKey
            ), existing.genesis.revision == revision else {
                throw LocalAccountProvisioningError.conflict
            }
            return PublicRepositoryGenesisInstallation(
                persisted: existing,
                wasAlreadyInstalled: true
            )
        }
    }

    private func reconcileDuplicateRegistration(
        did: String,
        handle: String,
        password: String,
        signingReference: AccountKeyReference,
        rotationReference: AccountKeyReference,
        publicGenesis: PersistedPublicRepositoryGenesis
    ) async throws -> AccountControlAccount {
        let existing: AccountControlAccount
        let existingReferences: (signing: AccountKeyReference, rotation: AccountKeyReference)
        do {
            guard let account = try await directory.account(did: did),
                  let references = try await directory.keyReferences(did: did) else {
                throw LocalAccountProvisioningError.conflict
            }
            existing = account
            existingReferences = references
        } catch let error as LocalAccountProvisioningError {
            throw error
        } catch {
            throw LocalAccountProvisioningError.unavailable
        }

        guard existing.status == .active,
              existing.canonicalHandle == handle,
              existing.publicGenesisCommitCID == publicGenesis.genesis.commitCID.string,
              existingReferences.signing == signingReference,
              existingReferences.rotation == rotationReference else {
            throw LocalAccountProvisioningError.conflict
        }

        // Delegate verification and its active-status finalization to the
        // established account service. This neither reads a verifier nor
        // turns a duplicate registration path into a password side channel.
        guard let authenticated = await directory.authenticate(
            handle: handle,
            password: password
        ), authenticated.account.did == did,
           authenticated.account.status == .active,
           authenticated.account.canonicalHandle == handle else {
            throw LocalAccountProvisioningError.conflict
        }
        return authenticated.account
    }

    private func existingControlAccount(
        did: String
    ) async throws -> AccountControlAccount? {
        do {
            return try await directory.account(did: did)
        } catch {
            throw LocalAccountProvisioningError.unavailable
        }
    }
}
