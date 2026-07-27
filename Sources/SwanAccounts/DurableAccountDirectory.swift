import Foundation
import SwanCore
import SwanStorage

/// The only successful result exposed by password authentication. Absence of
/// this value is intentionally indistinguishable across unknown accounts,
/// missing credentials, bad passwords, and every non-active lifecycle state.
public struct AccountAuthenticationSuccess: Sendable, Equatable {
    public let account: AccountControlAccount
    public let credentialWasRehashed: Bool

    public init(account: AccountControlAccount, credentialWasRehashed: Bool) {
        self.account = account
        self.credentialWasRehashed = credentialWasRehashed
    }
}

/// Durable registry, lifecycle, and local-password service. It never stores a
/// raw password and never returns a verifier through directory lookup APIs.
/// DID lifecycle/PLC operations remain outside this local control-plane slice.
public actor DurableAccountDirectory {
    private let store: any AccountControlStore
    private let passwordHasher: any PasswordHasher
    private let verificationExecutor: Argon2idVerificationExecutor
    private let keyProvisioner: AccountKeyProvisioner?

    public init(
        store: any AccountControlStore,
        passwordHasher: any PasswordHasher,
        verificationExecutor: Argon2idVerificationExecutor,
        keyProvisioner: AccountKeyProvisioner? = nil
    ) {
        self.store = store
        self.passwordHasher = passwordHasher
        self.verificationExecutor = verificationExecutor
        self.keyProvisioner = keyProvisioner
    }

    /// Creates key material in the configured external key store and records
    /// only its deterministic generation references in `control.sqlite`.
    public func provision(
        did: String,
        handle: String,
        password: String,
        now: Date = Date()
    ) async throws -> AccountControlAccount {
        let did = try AccountIdentifiers.validateDID(did)
        let handle = try AccountIdentifiers.canonicalHandle(handle)
        guard let keyProvisioner else {
            throw SwanError.unavailable("account key provisioner is not configured")
        }
        let keys = try await keyProvisioner.provisionInitial(accountDID: did)
        return try await registerProvisionedAccount(
            did: did,
            canonicalHandle: handle,
            password: password,
            signingReference: keys.signingReference,
            rotationReference: keys.rotationReference,
            now: now
        )
    }

    /// Registers an account whose external key material was provisioned by an
    /// operator or a previous durable workflow. This accepts raw password only
    /// at registration time; later credential changes are rehash upgrades
    /// performed immediately after a successful password verification.
    public func registerProvisionedAccount(
        did: String,
        canonicalHandle: String,
        password: String,
        signingReference: AccountKeyReference,
        rotationReference: AccountKeyReference,
        publicGenesisCommitCID: String? = nil,
        now: Date = Date()
    ) async throws -> AccountControlAccount {
        let did = try AccountIdentifiers.validateDID(did)
        let handle = try AccountIdentifiers.canonicalHandle(canonicalHandle)
        guard signingReference.accountDID == did,
              rotationReference.accountDID == did,
              signingReference.purpose == .signing,
              rotationReference.purpose == .rotation,
              signingReference.generation == rotationReference.generation else {
            throw SwanError.malformed("account key references do not match the account generation")
        }
        let verifier = try passwordHasher.hash(password)
        let registration = try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: verifier,
            signingKey: try controlReference(for: signingReference),
            rotationKey: try controlReference(for: rotationReference),
            publicGenesisCommitCID: publicGenesisCommitCID,
            createdAt: now
        )
        return try await store.createAccount(registration)
    }

    /// Normal account lookup returns control metadata only; a password
    /// verifier can never cross this API boundary.
    public func account(did: String) async throws -> AccountControlAccount? {
        try await store.account(did: AccountIdentifiers.validateDID(did))
    }

    /// Resolves a canonicalized handle without exposing credential material.
    public func resolve(handle: String) async throws -> AccountControlAccount? {
        try await store.account(canonicalHandle: AccountIdentifiers.canonicalHandle(handle))
    }

    /// Returns the external-key-store references reconstructed from durable
    /// generation metadata. This never reads or exports private key bytes.
    public func keyReferences(
        did: String
    ) async throws -> (signing: AccountKeyReference, rotation: AccountKeyReference)? {
        let did = try AccountIdentifiers.validateDID(did)
        guard let account = try await store.account(did: did),
              let signing = account.signingKey,
              let rotation = account.rotationKey else {
            return nil
        }
        guard signing.purpose == .signing, rotation.purpose == .rotation,
              signing.generation == rotation.generation,
              signing.reference == "\(signing.purpose.rawValue):\(signing.generation)",
              rotation.reference == "\(rotation.purpose.rawValue):\(rotation.generation)" else {
            throw AccountControlStoreError.malformedRecord
        }
        return (
            try AccountKeyReference(
                accountDID: did,
                purpose: .signing,
                generation: signing.generation
            ),
            try AccountKeyReference(
                accountDID: did,
                purpose: .rotation,
                generation: rotation.generation
            )
        )
    }

    /// Fails closed with `nil` for malformed handles, unknown accounts, missing
    /// verifiers, wrong passwords, verifier parse errors, and every non-active
    /// status. No public result differentiates those conditions.
    public func authenticate(
        handle: String,
        password: String,
        now: Date = Date()
    ) async -> AccountAuthenticationSuccess? {
        guard let handle = try? AccountIdentifiers.canonicalHandle(handle),
              let initialAccount = try? await store.account(canonicalHandle: handle),
              initialAccount.status.authorizesAccount,
              let credential = try? await store.credential(did: initialAccount.did) else {
            return nil
        }

        guard (try? await verificationExecutor.verify(password, encodedHash: credential.verifier)) == true else {
            return nil
        }

        let replacement: String?
        if (try? passwordHasher.needsRehash(credential.verifier)) == true,
           let upgraded = try? passwordHasher.hash(password) {
            replacement = upgraded
        } else {
            replacement = nil
        }
        guard let finalized = try? await store.finalizeAuthentication(
            did: initialAccount.did,
            expectedVerifier: credential.verifier,
            replacementVerifier: replacement,
            now: now
        ) else { return nil }
        return AccountAuthenticationSuccess(
            account: finalized.account,
            credentialWasRehashed: finalized.credentialWasReplaced
        )
    }

    public func transitionStatus(
        did: String,
        to status: AccountControlStatus,
        declaration: AccountLifecycleDeclaration = .init(),
        now: Date = Date()
    ) async throws -> AccountControlAccount {
        try await store.transitionStatus(
            did: AccountIdentifiers.validateDID(did),
            to: status,
            declaration: declaration,
            now: now
        )
    }

    private func controlReference(
        for reference: AccountKeyReference
    ) throws -> AccountControlKeyReference {
        let purpose: AccountControlKeyReference.Purpose = switch reference.purpose {
        case .signing: .signing
        case .rotation: .rotation
        }
        return try AccountControlKeyReference(
            purpose: purpose,
            generation: reference.generation
        )
    }
}
