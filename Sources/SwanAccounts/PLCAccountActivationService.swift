import Crypto
import Foundation
import SwanCore
import SwanPublicRepository
import SwanStorage

public enum PLCAccountActivationError: Error, Sendable, Equatable {
    case conflict
    case unavailable
}

struct PLCAccountActivationHooks: Sendable {
    var afterRegistration: (@Sendable () async throws -> Void)?
}

/// Turns one remotely submitted preparation into one active local account.
/// Network proof, per-account repository reads and control registration are
/// deliberately separate awaits: no SQLite transaction spans PLC, DNS, or
/// HTTP I/O.
public actor PLCAccountActivationService {
    private let intentStore: any PLCAccountPreparationIntentStore
    private let accountStoreOpener: any PLCAccountPreparationAccountStoreOpener
    private let keyStore: any AccountKeyStore
    private let plcClient: any PLCClient
    private let handleVerifier: any PLCHandleVerifying
    private let directory: DurableAccountDirectory
    private let hooks: PLCAccountActivationHooks

    public init(
        intentStore: any PLCAccountPreparationIntentStore,
        accountStoreOpener: any PLCAccountPreparationAccountStoreOpener,
        keyStore: any AccountKeyStore,
        plcClient: any PLCClient,
        handleVerifier: any PLCHandleVerifying,
        directory: DurableAccountDirectory
    ) {
        self.intentStore = intentStore
        self.accountStoreOpener = accountStoreOpener
        self.keyStore = keyStore
        self.plcClient = plcClient
        self.handleVerifier = handleVerifier
        self.directory = directory
        hooks = .init()
    }

    init(
        intentStore: any PLCAccountPreparationIntentStore,
        accountStoreOpener: any PLCAccountPreparationAccountStoreOpener,
        keyStore: any AccountKeyStore,
        plcClient: any PLCClient,
        handleVerifier: any PLCHandleVerifying,
        directory: DurableAccountDirectory,
        hooks: PLCAccountActivationHooks
    ) {
        self.intentStore = intentStore
        self.accountStoreOpener = accountStoreOpener
        self.keyStore = keyStore
        self.plcClient = plcClient
        self.handleVerifier = handleVerifier
        self.directory = directory
        self.hooks = hooks
    }

    public func activate(
        requestID: String,
        password: String,
        now: Date = Date()
    ) async throws -> LocalAccountInstallation {
        let intent = try await submittedIntent(requestID: requestID)
        let store = try await openStore(did: intent.did)
        let journal = try await submittedJournal(store: store, intent: intent)
        let keys = try await verifiedKeys(journal: journal, intent: intent)
        let operation = try verifiedGenesisOperation(
            journal: journal,
            intent: intent,
            keys: keys
        )
        let publicGenesis = try await verifiedPublicGenesis(
            store: store,
            journal: journal,
            intent: intent,
            keys: keys
        )

        // The audit check rejects a tombstone or any post-genesis mutation.
        // `fetchState` then authenticates the projected PLC document against
        // that audit in the production Task 13 client.
        let state = try await authenticatedPLCState(
            intent: intent,
            journal: journal,
            operation: operation,
            keys: keys
        )
        try await persistGenesisHistoryIfSupported(
            store: store,
            operation: operation,
            now: now
        )
        do {
            _ = try await handleVerifier.verify(
                plcState: state,
                expectedDID: intent.did,
                handle: intent.canonicalHandle,
                pdsOrigin: intent.pdsOrigin
            )
        } catch let error as ATHandleVerificationError
            where error == .verificationFailed {
            throw PLCAccountActivationError.conflict
        } catch {
            throw PLCAccountActivationError.unavailable
        }

        let installation: LocalAccountInstallation
        do {
            installation = try await LocalAccountProvisioner(
                directory: directory,
                publicGenesisStore: store,
                keyProvisioner: AccountKeyProvisioner(keyStore: keyStore),
                keyStore: keyStore
            ).install(
                did: intent.did,
                handle: intent.canonicalHandle,
                password: password,
                revision: journal.repositoryRevision,
                now: now
            )
        } catch let error as LocalAccountProvisioningError {
            switch error {
            case .conflict:
                throw PLCAccountActivationError.conflict
            case .unavailable:
                throw PLCAccountActivationError.unavailable
            }
        } catch let error as AccountControlStoreError {
            switch error {
            case .duplicateDID, .duplicateHandle, .invalidInput,
                    .invalidStatus, .invalidTransition, .notFound:
                throw PLCAccountActivationError.conflict
            case .malformedRecord, .unavailable:
                throw PLCAccountActivationError.unavailable
            }
        } catch {
            throw PLCAccountActivationError.unavailable
        }
        do {
            try await hooks.afterRegistration?()
        } catch {
            throw PLCAccountActivationError.unavailable
        }

        guard installation.account.did == intent.did,
              installation.account.canonicalHandle == intent.canonicalHandle,
              installation.account.status == .active,
              installation.account.publicGenesisCommitCID
                == publicGenesis.genesis.commitCID.string,
              installation.publicGenesis == publicGenesis,
              let references = try? await directory.keyReferences(did: intent.did),
              references.signing == keys.signingReference,
              references.rotation == keys.rotationReference,
              let authenticated = await directory.authenticate(
                  handle: intent.canonicalHandle,
                  password: password,
                  now: now
              ),
              authenticated.account == installation.account else {
            throw PLCAccountActivationError.conflict
        }
        return installation
    }

    private func persistGenesisHistoryIfSupported(
        store: any PLCAccountPreparationAccountStore,
        operation: PLCSignedOperation,
        now: Date
    ) async throws {
        guard let historyStore = store as? any PublicPLCIdentityHistoryStore,
              let regular = operation.regular else {
            return
        }
        do {
            let entry = try PublicPLCOperationHistoryEntry(
                cid: try operation.cid.string,
                previousCID: operation.prev,
                canonicalJSON: try operation.canonicalJSON,
                createdAt: now,
                signingKeyGeneration: 1,
                rotationKeyGeneration: 1
            )
            _ = try await historyStore.installPublicPLCOperation(entry)
            guard regular.prev == nil else {
                throw PLCAccountActivationError.conflict
            }
        } catch let error as PLCAccountActivationError {
            throw error
        } catch let error as SwanError {
            if case .conflict = error {
                throw PLCAccountActivationError.conflict
            }
            throw PLCAccountActivationError.unavailable
        } catch {
            throw PLCAccountActivationError.unavailable
        }
    }

    private func submittedIntent(
        requestID: String
    ) async throws -> PLCAccountPreparationIntent {
        do {
            guard let intent = try await intentStore.plcAccountPreparationIntent(
                requestID: requestID
            ), intent.stage == .submitted else {
                throw PLCAccountActivationError.conflict
            }
            return intent
        } catch let error as PLCAccountActivationError {
            throw error
        } catch let error as PLCAccountPreparationStoreError
            where error == .invalidInput || error == .notFound
                || error == .conflict || error == .invalidTransition {
            throw PLCAccountActivationError.conflict
        } catch {
            throw PLCAccountActivationError.unavailable
        }
    }

    private func openStore(
        did: String
    ) async throws -> any PLCAccountPreparationAccountStore {
        do {
            return try await accountStoreOpener.openPLCAccountPreparationStore(
                did: did
            )
        } catch {
            throw PLCAccountActivationError.unavailable
        }
    }

    private func submittedJournal(
        store: any PLCAccountPreparationAccountStore,
        intent: PLCAccountPreparationIntent
    ) async throws -> PLCAccountPreparationJournal {
        do {
            guard let journal = try await store.plcAccountPreparationJournal(),
                  journal.stage == .submitted,
                  journal.requestID == intent.requestID,
                  journal.canonicalHandle == intent.canonicalHandle,
                  journal.pdsOrigin == intent.pdsOrigin,
                  journal.repositoryRevision == intent.repositoryRevision,
                  journal.publicGenesisCommitCID != nil else {
                throw PLCAccountActivationError.conflict
            }
            return journal
        } catch let error as PLCAccountActivationError {
            throw error
        } catch {
            throw PLCAccountActivationError.unavailable
        }
    }

    private func verifiedKeys(
        journal: PLCAccountPreparationJournal,
        intent: PLCAccountPreparationIntent
    ) async throws -> ProvisionedAccountKeys {
        do {
            let keys = try await AccountKeyProvisioner(keyStore: keyStore)
                .resumeProvisioning(accountDID: intent.did, generation: 1)
            guard journal.signingKey == (try controlReference(keys.signingReference)),
                  journal.rotationKey == (try controlReference(keys.rotationReference)) else {
                throw PLCAccountActivationError.conflict
            }
            return keys
        } catch let error as PLCAccountActivationError {
            throw error
        } catch {
            throw PLCAccountActivationError.unavailable
        }
    }

    private func verifiedGenesisOperation(
        journal: PLCAccountPreparationJournal,
        intent: PLCAccountPreparationIntent,
        keys: ProvisionedAccountKeys
    ) throws -> PLCSignedOperation {
        do {
            let operation = try PLCOperationCodec.reconstructGenesis(
                signingDIDKey: journal.operation.signingDIDKey,
                rotationDIDKey: journal.operation.rotationDIDKey,
                canonicalHandle: journal.canonicalHandle,
                pdsOrigin: journal.pdsOrigin,
                signature: journal.operation.signature
            )
            try PLCOperationCodec.verifyGenesis(operation, expectedDID: intent.did)
            guard try operation.cid.string == intent.operationCID,
                  let regular = operation.regular,
                  regular.verificationMethods == [
                      "atproto": P256DIDKey(publicKey: try P256.Signing.PublicKey(
                          x963Representation: keys.signingPublicKey
                      )).value,
                  ],
                  regular.rotationKeys == [
                      P256DIDKey(publicKey: try P256.Signing.PublicKey(
                          x963Representation: keys.rotationPublicKey
                      )).value,
                  ] else {
                throw PLCAccountActivationError.conflict
            }
            return operation
        } catch let error as PLCAccountActivationError {
            throw error
        } catch {
            throw PLCAccountActivationError.conflict
        }
    }

    private func verifiedPublicGenesis(
        store: any PLCAccountPreparationAccountStore,
        journal: PLCAccountPreparationJournal,
        intent: PLCAccountPreparationIntent,
        keys: ProvisionedAccountKeys
    ) async throws -> PersistedPublicRepositoryGenesis {
        do {
            let material = try await keyStore.key(for: keys.signingReference)
            let signingKey = try P256.Signing.PrivateKey(rawRepresentation: material)
            guard signingKey.publicKey.x963Representation == keys.signingPublicKey,
                  let genesis = try await store.loadPublicRepositoryGenesis(
                      did: intent.did,
                      signingPublicKey: signingKey.publicKey
                  ),
                  genesis.genesis.did == intent.did,
                  genesis.genesis.revision == journal.repositoryRevision,
                  genesis.genesis.commitCID.string
                    == journal.publicGenesisCommitCID else {
                throw PLCAccountActivationError.conflict
            }
            return genesis
        } catch let error as PLCAccountActivationError {
            throw error
        } catch let error as PublicRepositoryGenesisStoreError
            where error == .conflictingGenesis || error == .ownershipMismatch {
            throw PLCAccountActivationError.conflict
        } catch {
            throw PLCAccountActivationError.unavailable
        }
    }

    private func authenticatedPLCState(
        intent: PLCAccountPreparationIntent,
        journal: PLCAccountPreparationJournal,
        operation: PLCSignedOperation,
        keys: ProvisionedAccountKeys
    ) async throws -> PLCDocumentData {
        do {
            let audit = try await plcClient.fetchAudit(did: intent.did)
            guard !audit.isEmpty,
                  audit.allSatisfy({ $0.did == intent.did }),
                  let terminal = audit.last(where: { !$0.nullified }),
                  terminal == audit.last,
                  terminal.cid == intent.operationCID,
                  terminal.operation == operation,
                  terminal.operation.regular != nil else {
                throw PLCAccountActivationError.conflict
            }
            try PLCOperationCodec.verifyGenesis(
                terminal.operation,
                expectedDID: intent.did
            )
            let state = try await plcClient.fetchState(did: intent.did)
            guard let regular = operation.regular,
                  state.did == intent.did,
                  state.rotationKeys == regular.rotationKeys,
                  state.verificationMethods == regular.verificationMethods,
                  state.alsoKnownAs == ["at://\(journal.canonicalHandle)"],
                  state.services == [
                      "atproto_pds": PLCService(
                          type: "AtprotoPersonalDataServer",
                          endpoint: journal.pdsOrigin
                      ),
                  ],
                  keys.signingReference.accountDID == state.did,
                  keys.rotationReference.accountDID == state.did else {
                throw PLCAccountActivationError.conflict
            }
            return state
        } catch let error as PLCAccountActivationError {
            throw error
        } catch {
            throw PLCAccountActivationError.unavailable
        }
    }

    private func controlReference(
        _ reference: AccountKeyReference
    ) throws -> AccountControlKeyReference {
        try .init(
            purpose: reference.purpose == .signing ? .signing : .rotation,
            generation: reference.generation
        )
    }
}
