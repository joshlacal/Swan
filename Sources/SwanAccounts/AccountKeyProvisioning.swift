import Crypto
import Foundation
import SwanCore

public struct ProvisionedAccountKeys: Sendable, Equatable {
    public let signingReference: AccountKeyReference
    public let rotationReference: AccountKeyReference
    public let signingPublicKey: Data
    public let rotationPublicKey: Data
}

public struct AccountKeyProvisioner: Sendable {
    private let keyStore: any AccountKeyStore

    public init(keyStore: any AccountKeyStore) {
        self.keyStore = keyStore
    }

    public func provisionInitial(accountDID: String) async throws -> ProvisionedAccountKeys {
        try await provision(accountDID: accountDID, generation: 1)
    }

    public func provisionRotation(
        accountDID: String,
        generation: UInt64
    ) async throws -> ProvisionedAccountKeys {
        guard generation > 1 else {
            throw SwanError.malformed("account key rotation requires an explicit higher generation")
        }
        return try await provision(accountDID: accountDID, generation: generation)
    }

    public func resumeProvisioning(
        accountDID: String,
        generation: UInt64
    ) async throws -> ProvisionedAccountKeys {
        let signingReference = try AccountKeyReference(
            accountDID: accountDID,
            purpose: .signing,
            generation: generation
        )
        let rotationReference = try AccountKeyReference(
            accountDID: accountDID,
            purpose: .rotation,
            generation: generation
        )
        let signingData = try await keyStore.key(for: signingReference)
        let rotationData = try await keyStore.key(for: rotationReference)
        let signingKey: P256.Signing.PrivateKey
        let rotationKey: P256.Signing.PrivateKey
        do {
            signingKey = try P256.Signing.PrivateKey(rawRepresentation: signingData)
            rotationKey = try P256.Signing.PrivateKey(rawRepresentation: rotationData)
        } catch {
            throw SwanError.malformed("stored account provisioning key is not a valid P-256 private key")
        }
        guard signingData != rotationData else {
            throw SwanError.malformed("stored account provisioning keys are not distinct")
        }
        return ProvisionedAccountKeys(
            signingReference: signingReference,
            rotationReference: rotationReference,
            signingPublicKey: signingKey.publicKey.x963Representation,
            rotationPublicKey: rotationKey.publicKey.x963Representation
        )
    }

    private func provision(
        accountDID: String,
        generation: UInt64
    ) async throws -> ProvisionedAccountKeys {
        let signingKey = P256.Signing.PrivateKey()
        let rotationKey = P256.Signing.PrivateKey()
        guard signingKey.rawRepresentation != rotationKey.rawRepresentation else {
            throw SwanError.unavailable("P-256 key generation returned duplicate account keys")
        }

        let signingReference = try AccountKeyReference(
            accountDID: accountDID,
            purpose: .signing,
            generation: generation
        )
        let rotationReference = try AccountKeyReference(
            accountDID: accountDID,
            purpose: .rotation,
            generation: generation
        )
        do {
            try await keyStore.createBatch([
                try AccountKeyMaterial(
                    reference: signingReference,
                    key: signingKey.rawRepresentation
                ),
                try AccountKeyMaterial(
                    reference: rotationReference,
                    key: rotationKey.rawRepresentation
                ),
            ])
        } catch let error as SwanError where error == .conflict(expected: 0, actual: 1) {
            return try await resumeProvisioning(
                accountDID: accountDID,
                generation: generation
            )
        }

        return ProvisionedAccountKeys(
            signingReference: signingReference,
            rotationReference: rotationReference,
            signingPublicKey: signingKey.publicKey.x963Representation,
            rotationPublicKey: rotationKey.publicKey.x963Representation
        )
    }
}
