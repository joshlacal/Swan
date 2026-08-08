import Crypto
import Foundation
import SwanCore
import SwanStorage

public struct RotatedPLCAccountIdentity: Sendable, Equatable {
    public let account: AccountControlAccount
    public let operation: PLCSignedOperation
    public let generation: UInt64

    public init(
        account: AccountControlAccount,
        operation: PLCSignedOperation,
        generation: UInt64
    ) throws {
        guard generation > 1, operation.prev != nil else {
            throw SwanError.malformed("PLC rotation result is not a rotation")
        }
        self.account = account
        self.operation = operation
        self.generation = generation
    }
}

public enum PLCAccountRotationError: Error, Sendable, Equatable {
    case conflict
    case unavailable
}

/// Performs one authenticated PLC key rotation. The remote operation is
/// submitted and verified before the local control references are promoted;
/// the account-history append precedes that promotion so a crash can only
/// leave a recoverable pending rotation, never a public identity that lacks
/// an authenticated operation body.
public actor PLCAccountRotationService {
    private let controlStore: any AccountControlStore
    private let accountStoreOpener: any PLCAccountPreparationAccountStoreOpener
    private let keyStore: any AccountKeyStore
    private let plcClient: any PLCClient
    private let lifecycleEmitter: (any PublicLifecycleEventEmitting)?

    public init(
        controlStore: any AccountControlStore,
        accountStoreOpener: any PLCAccountPreparationAccountStoreOpener,
        keyStore: any AccountKeyStore,
        plcClient: any PLCClient,
        lifecycleEmitter: (any PublicLifecycleEventEmitting)? = nil
    ) {
        self.controlStore = controlStore
        self.accountStoreOpener = accountStoreOpener
        self.keyStore = keyStore
        self.plcClient = plcClient
        self.lifecycleEmitter = lifecycleEmitter
    }

    public func rotate(
        did rawDID: String,
        now: Date = Date()
    ) async throws -> RotatedPLCAccountIdentity {
        let did: String
        do {
            did = try AccountIdentifiers.validateDID(rawDID)
        } catch {
            throw PLCAccountRotationError.conflict
        }

        let account: AccountControlAccount
        do {
            guard let loaded = try await controlStore.account(did: did),
                  loaded.status == .active,
                  let currentSigning = loaded.signingKey,
                  let currentRotation = loaded.rotationKey,
                  currentSigning.generation == currentRotation.generation else {
                throw PLCAccountRotationError.conflict
            }
            account = loaded
        } catch let error as PLCAccountRotationError {
            throw error
        } catch {
            throw PLCAccountRotationError.unavailable
        }

        guard let currentSigning = account.signingKey,
              account.rotationKey != nil,
              currentSigning.generation < UInt64.max else {
            throw PLCAccountRotationError.conflict
        }
        let expectedGeneration = currentSigning.generation
        let nextGeneration = expectedGeneration + 1

        let store: any PLCAccountPreparationAccountStore
        do {
            store = try await accountStoreOpener.openPLCAccountPreparationStore(did: did)
        } catch {
            throw PLCAccountRotationError.unavailable
        }
        guard let historyStore = store as? any PublicPLCIdentityHistoryStore else {
            throw PLCAccountRotationError.unavailable
        }

        let history: [PublicPLCOperationHistoryEntry]
        do {
            history = try await ensureHistory(
                store: store,
                historyStore: historyStore,
                account: account,
                now: now
            )
        } catch let error as PLCAccountRotationError {
            throw error
        } catch {
            throw PLCAccountRotationError.unavailable
        }

        guard let terminalEntry = history.last,
              terminalEntry.signingKeyGeneration == expectedGeneration,
              terminalEntry.rotationKeyGeneration == expectedGeneration else {
            // A previous process may have appended a rotation before it
            // crashed during control-store promotion. Recover that exact
            // operation instead of submitting a second branch.
            if let pending = history.last,
               pending.signingKeyGeneration == nextGeneration,
               pending.rotationKeyGeneration == nextGeneration {
                return try await recoverPendingRotation(
                    pending: pending,
                    account: account,
                    expectedGeneration: expectedGeneration,
                    now: now
                )
            }
            throw PLCAccountRotationError.conflict
        }

        let oldRotationKey: P256.Signing.PrivateKey
        do {
            oldRotationKey = try P256.Signing.PrivateKey(
                rawRepresentation: try await keyStore.key(
                    for: try AccountKeyReference(
                        accountDID: did,
                        purpose: .rotation,
                        generation: expectedGeneration
                    )
                )
            )
        } catch {
            throw PLCAccountRotationError.unavailable
        }

        let nextKeys: ProvisionedAccountKeys
        do {
            nextKeys = try await AccountKeyProvisioner(keyStore: keyStore)
                .provisionRotation(accountDID: did, generation: nextGeneration)
        } catch {
            throw PLCAccountRotationError.unavailable
        }

        let terminalOperation: PLCSignedOperation
        do {
            terminalOperation = try PLCOperationCodec.decodeSignedJSON(
                terminalEntry.canonicalJSON
            )
        } catch {
            throw PLCAccountRotationError.unavailable
        }
        let rotatedOperation: PLCSignedOperation
        do {
            rotatedOperation = try makeRotation(
                previous: terminalOperation,
                signingPublicKey: try P256.Signing.PublicKey(
                    x963Representation: nextKeys.signingPublicKey
                ),
                rotationPublicKey: try P256.Signing.PublicKey(
                    x963Representation: nextKeys.rotationPublicKey
                ),
                using: oldRotationKey
            )
        } catch {
            throw PLCAccountRotationError.conflict
        }

        let entry: PublicPLCOperationHistoryEntry
        do {
            let proposedEntry = try PublicPLCOperationHistoryEntry(
                cid: try rotatedOperation.cid.string,
                previousCID: rotatedOperation.prev,
                canonicalJSON: try rotatedOperation.canonicalJSON,
                createdAt: now,
                signingKeyGeneration: nextGeneration,
                rotationKeyGeneration: nextGeneration
            )
            _ = try await historyStore.installPublicPLCOperation(proposedEntry)
            guard let persistedEntry = try await historyStore
                .publicPLCOperationHistory().last,
                  persistedEntry.cid == proposedEntry.cid else {
                throw PLCAccountRotationError.unavailable
            }
            entry = persistedEntry
        } catch let error as SwanError where isConflict(error) {
            throw PLCAccountRotationError.conflict
        } catch {
            throw PLCAccountRotationError.unavailable
        }

        // Record the exact pending operation before network I/O. If the
        // process dies after PLC accepts it but before control promotion,
        // the next invocation can replay this durable operation instead of
        // generating a branch or depending on a signature being repeatable.
        try await submitAndVerify(
            operation: rotatedOperation,
            did: did,
            expectedPrevious: terminalEntry.cid
        )

        let request: AccountControlKeyRotationRequest
        do {
            request = try AccountControlKeyRotationRequest(
                expectedGeneration: expectedGeneration,
                signingKey: try AccountControlKeyReference(
                    purpose: .signing,
                    generation: nextGeneration
                ),
                rotationKey: try AccountControlKeyReference(
                    purpose: .rotation,
                    generation: nextGeneration
                )
            )
        } catch {
            throw PLCAccountRotationError.conflict
        }
        return try await promote(
            account: account,
            operation: rotatedOperation,
            generation: nextGeneration,
            request: request,
            materialTime: entry.createdAt,
            now: now
        )
    }

    private func ensureHistory(
        store: any PLCAccountPreparationAccountStore,
        historyStore: any PublicPLCIdentityHistoryStore,
        account: AccountControlAccount,
        now: Date
    ) async throws -> [PublicPLCOperationHistoryEntry] {
        let existing = try await historyStore.publicPLCOperationHistory()
        if !existing.isEmpty {
            _ = try SwanPublicPLCGenesisVerifier().verifyIdentityHistory(
                existing,
                expectedDID: account.did
            )
            return existing
        }
        guard let journal = try await store.plcAccountPreparationJournal(),
              journal.stage == .submitted,
              journal.publicGenesisCommitCID == account.publicGenesisCommitCID else {
            throw PLCAccountRotationError.conflict
        }
        let operation = try PLCOperationCodec.reconstructGenesis(
            signingDIDKey: journal.operation.signingDIDKey,
            rotationDIDKey: journal.operation.rotationDIDKey,
            canonicalHandle: journal.canonicalHandle,
            pdsOrigin: journal.pdsOrigin,
            signature: journal.operation.signature
        )
        try PLCOperationCodec.verifyGenesis(operation, expectedDID: account.did)
        let entry = try PublicPLCOperationHistoryEntry(
            cid: try operation.cid.string,
            previousCID: nil,
            canonicalJSON: try operation.canonicalJSON,
            createdAt: now,
            signingKeyGeneration: 1,
            rotationKeyGeneration: 1
        )
        _ = try await historyStore.installPublicPLCOperation(entry)
        let history = try await historyStore.publicPLCOperationHistory()
        _ = try SwanPublicPLCGenesisVerifier().verifyIdentityHistory(
            history,
            expectedDID: account.did
        )
        return history
    }

    private func recoverPendingRotation(
        pending: PublicPLCOperationHistoryEntry,
        account: AccountControlAccount,
        expectedGeneration: UInt64,
        now: Date
    ) async throws -> RotatedPLCAccountIdentity {
        let operation: PLCSignedOperation
        do {
            operation = try PLCOperationCodec.decodeSignedJSON(pending.canonicalJSON)
            try await submitAndVerify(
                operation: operation,
                did: account.did,
                expectedPrevious: pending.previousCID
            )
        } catch {
            throw PLCAccountRotationError.unavailable
        }
        let request = try AccountControlKeyRotationRequest(
            expectedGeneration: expectedGeneration,
            signingKey: try AccountControlKeyReference(
                purpose: .signing,
                generation: expectedGeneration + 1
            ),
            rotationKey: try AccountControlKeyReference(
                purpose: .rotation,
                generation: expectedGeneration + 1
            )
        )
        return try await promote(
            account: account,
            operation: operation,
            generation: expectedGeneration + 1,
            request: request,
            materialTime: pending.createdAt,
            now: now
        )
    }

    private func makeRotation(
        previous: PLCSignedOperation,
        signingPublicKey: P256.Signing.PublicKey,
        rotationPublicKey: P256.Signing.PublicKey,
        using rotationKey: P256.Signing.PrivateKey
    ) throws -> PLCSignedOperation {
        guard let prior = previous.regular,
              let previousCID = try? previous.cid.string else {
            throw SwanError.malformed("PLC rotation parent is invalid")
        }
        let unsigned = try PLCUnsignedRegularOperation(
            rotationKeys: [P256DIDKey(publicKey: rotationPublicKey).value],
            verificationMethods: [
                "atproto": P256DIDKey(publicKey: signingPublicKey).value,
            ],
            alsoKnownAs: prior.alsoKnownAs,
            services: prior.services,
            prev: previousCID
        )
        return try PLCOperationCodec.sign(.regular(unsigned), using: rotationKey)
    }

    private func submitAndVerify(
        operation: PLCSignedOperation,
        did: String,
        expectedPrevious: String?
    ) async throws {
        guard operation.prev == expectedPrevious else {
            throw PLCAccountRotationError.conflict
        }
        // A process can die after the remote accepts an operation but before
        // local history/control promotion. Treat submit as idempotent and
        // let the authenticated audit below decide whether the exact
        // operation is already the terminal state.
        do {
            try await plcClient.submit(did: did, operation: operation)
        } catch {
            // Continue to fetch the audit. A duplicate, replay, or transport
            // error is only safe to ignore if the audit proves acceptance.
        }
        do {
            let audit = try await plcClient.fetchAudit(did: did)
            guard let terminal = audit.last(where: { !$0.nullified }),
                  terminal == audit.last,
                  terminal.operation == operation,
                  terminal.cid == (try operation.cid.string) else {
                throw PLCAccountRotationError.conflict
            }
            let state = try await plcClient.fetchState(did: did)
            guard let regular = operation.regular,
                  state.did == did,
                  state.rotationKeys == regular.rotationKeys,
                  state.verificationMethods == regular.verificationMethods,
                  state.alsoKnownAs == regular.alsoKnownAs,
                  state.services == regular.services else {
                throw PLCAccountRotationError.conflict
            }
        } catch let error as PLCAccountRotationError {
            throw error
        } catch {
            throw PLCAccountRotationError.unavailable
        }
    }

    private func promote(
        account: AccountControlAccount,
        operation: PLCSignedOperation,
        generation: UInt64,
        request: AccountControlKeyRotationRequest,
        materialTime: Date,
        now: Date
    ) async throws -> RotatedPLCAccountIdentity {
        guard let rotationStore = controlStore as? any AccountControlKeyRotationStore else {
            throw PLCAccountRotationError.unavailable
        }
        do {
            let operationCID = try operation.cid.string
            let updated = try await rotationStore.rotateAccountKeys(
                did: account.did,
                request: request,
                emitting: lifecycleEmitter == nil ? nil : .init(
                    plcOperationCID: operationCID,
                    handle: nil,
                    materialTime: materialTime
                ),
                now: now
            )
            return try RotatedPLCAccountIdentity(
                account: updated,
                operation: operation,
                generation: generation
            )
        } catch let error as AccountControlStoreError {
            switch error {
            case .invalidTransition, .duplicateDID, .duplicateHandle,
                    .invalidInput, .invalidStatus, .notFound:
                throw PLCAccountRotationError.conflict
            case .malformedRecord, .unavailable:
                throw PLCAccountRotationError.unavailable
            }
        } catch {
            throw PLCAccountRotationError.unavailable
        }
    }
}

private func isConflict(_ error: SwanError) -> Bool {
    if case .conflict = error { return true }
    return false
}
