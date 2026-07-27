import Crypto
import Foundation
import SwanCore
import SwanPublicRepository
import SwanStorage

public struct PreparedPLCAccountIdentity: Sendable, Equatable {
    public let requestID: String
    public let did: String
    public let canonicalHandle: String
    public let pdsOrigin: String
    public let repositoryRevision: String
    public let plcOperationCID: String
    public let publicGenesisCommitCID: String
    public let signingReference: AccountKeyReference
    public let rotationReference: AccountKeyReference
}

public enum PLCAccountPreparationError: Error, Sendable, Equatable {
    case conflict
    case unavailable
    case remoteMismatch
}

struct PLCAccountPreparationHooks: Sendable {
    var afterIntentReserved: (@Sendable () async throws -> Void)?
    var afterRepositoryInstalled: (@Sendable () async throws -> Void)?
    var afterPLCSubmitted: (@Sendable () async throws -> Void)?
}

/// Creates a durable, remotely authenticated identity package without adding
/// an account registry row. Each await to the PLC client is separated from
/// the bounded storage calls, so no network operation can occur inside either
/// SQLite transaction.
public actor PLCAccountPreparationService {
    private let intentStore: any PLCAccountPreparationIntentStore
    private let accountStoreOpener: any PLCAccountPreparationAccountStoreOpener
    private let keyProvisioner: AccountKeyProvisioner
    private let keyStore: any AccountKeyStore
    private let plcClient: any PLCClient
    private let hooks: PLCAccountPreparationHooks

    public init(
        intentStore: any PLCAccountPreparationIntentStore,
        accountStoreOpener: any PLCAccountPreparationAccountStoreOpener,
        keyStore: any AccountKeyStore,
        plcClient: any PLCClient
    ) {
        self.intentStore = intentStore
        self.accountStoreOpener = accountStoreOpener
        keyProvisioner = AccountKeyProvisioner(keyStore: keyStore)
        self.keyStore = keyStore
        self.plcClient = plcClient
        hooks = .init()
    }

    init(
        intentStore: any PLCAccountPreparationIntentStore,
        accountStoreOpener: any PLCAccountPreparationAccountStoreOpener,
        keyStore: any AccountKeyStore,
        plcClient: any PLCClient,
        hooks: PLCAccountPreparationHooks
    ) {
        self.intentStore = intentStore
        self.accountStoreOpener = accountStoreOpener
        keyProvisioner = AccountKeyProvisioner(keyStore: keyStore)
        self.keyStore = keyStore
        self.plcClient = plcClient
        self.hooks = hooks
    }

    public func prepare(
        requestID: String,
        handle rawHandle: String,
        pdsOrigin rawPDSOrigin: URL,
        repositoryRevision: String,
        now: Date = Date()
    ) async throws -> PreparedPLCAccountIdentity {
        let handle: String
        do {
            guard !requestID.isEmpty, requestID.utf8.count <= 128,
                  requestID.utf8.allSatisfy({
                      ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                          || ($0 >= 97 && $0 <= 122) || [45, 46, 58, 95].contains($0)
                  }) else {
                throw PLCAccountPreparationError.conflict
            }
            handle = try AccountIdentifiers.canonicalHandle(rawHandle)
            try PublicRepositoryGenesisCodec.validateRevision(repositoryRevision)
        } catch {
            throw PLCAccountPreparationError.conflict
        }

        let intent: PLCAccountPreparationIntent
        if let existing = try await loadIntent(requestID: requestID) {
            try requireSameInputs(
                existing,
                requestID: requestID,
                handle: handle,
                pdsOrigin: rawPDSOrigin,
                repositoryRevision: repositoryRevision
            )
            intent = existing
        } else {
            intent = try await createInitialPreparation(
                requestID: requestID,
                handle: handle,
                pdsOrigin: rawPDSOrigin,
                repositoryRevision: repositoryRevision
            )
        }

        try await hooks.afterIntentReserved?()
        let store = try await openStore(did: intent.did)
        var journal = try await requireJournal(store: store, intent: intent)
        let keys = try await loadAndVerifyKeys(journal: journal)
        let signedOperation = try verifiedOperation(journal: journal, keys: keys)

        let genesis = try await installOrVerifyPublicGenesis(
            store: store,
            journal: journal,
            keys: keys,
            now: now
        )
        try await hooks.afterRepositoryInstalled?()

        journal = try await advanceJournal(
            journal,
            store: store,
            to: .repositoryInstalled,
            publicGenesisCommitCID: genesis.genesis.commitCID.string
        )
        var currentIntent = try await advanceIntent(
            intent,
            to: .repositoryInstalled
        )
        journal = try await advanceJournal(
            journal,
            store: store,
            to: .submissionPending,
            publicGenesisCommitCID: genesis.genesis.commitCID.string
        )
        currentIntent = try await advanceIntent(currentIntent, to: .submissionPending)

        if let audit = try await plcClient.fetchAuditIfPresent(did: intent.did) {
            try await verifyRemoteIdentity(
                audit: audit,
                journal: journal,
                operation: signedOperation,
                keys: keys,
                publicGenesis: genesis.genesis
            )
        } else {
            try await plcClient.submit(did: intent.did, operation: signedOperation)
            try await hooks.afterPLCSubmitted?()
            let audit = try await plcClient.fetchAudit(did: intent.did)
            try await verifyRemoteIdentity(
                audit: audit,
                journal: journal,
                operation: signedOperation,
                keys: keys,
                publicGenesis: genesis.genesis
            )
        }

        journal = try await advanceJournal(
            journal,
            store: store,
            to: .submitted,
            publicGenesisCommitCID: genesis.genesis.commitCID.string
        )
        currentIntent = try await advanceIntent(currentIntent, to: .submitted)
        guard journal.stage == .submitted, currentIntent.stage == .submitted else {
            throw PLCAccountPreparationError.unavailable
        }
        return PreparedPLCAccountIdentity(
            requestID: requestID,
            did: intent.did,
            canonicalHandle: handle,
            pdsOrigin: intent.pdsOrigin,
            repositoryRevision: repositoryRevision,
            plcOperationCID: intent.operationCID,
            publicGenesisCommitCID: genesis.genesis.commitCID.string,
            signingReference: keys.signingReference,
            rotationReference: keys.rotationReference
        )
    }

    private func createInitialPreparation(
        requestID: String,
        handle: String,
        pdsOrigin: URL,
        repositoryRevision: String
    ) async throws -> PLCAccountPreparationIntent {
        let signingKey = P256.Signing.PrivateKey()
        let rotationKey = P256.Signing.PrivateKey()
        guard signingKey.rawRepresentation != rotationKey.rawRepresentation else {
            throw PLCAccountPreparationError.unavailable
        }
        let unsigned: PLCUnsignedRegularOperation
        let operation: PLCSignedOperation
        let did: String
        do {
            unsigned = try PLCATProfile.regularOperation(
                handle: handle,
                signingPublicKey: signingKey.publicKey,
                rotationPublicKeys: [rotationKey.publicKey],
                pdsOrigin: pdsOrigin,
                prev: nil
            )
            operation = try PLCOperationCodec.sign(.regular(unsigned), using: rotationKey)
            did = try PLCOperationCodec.genesisDID(for: operation)
        } catch {
            throw PLCAccountPreparationError.conflict
        }
        guard let regular = operation.regular,
              let canonicalOrigin = regular.services["atproto_pds"]?.endpoint else {
            throw PLCAccountPreparationError.unavailable
        }
        let operationCID = try operation.cid.string
        let keys: ProvisionedAccountKeys
        do {
            keys = try await keyProvisioner.installInitial(
                accountDID: did,
                signingKey: signingKey,
                rotationKey: rotationKey
            )
        } catch {
            throw PLCAccountPreparationError.unavailable
        }
        let intent: PLCAccountPreparationIntent
        let journal: PLCAccountPreparationJournal
        do {
            intent = try PLCAccountPreparationIntent(
                requestID: requestID,
                did: did,
                canonicalHandle: handle,
                pdsOrigin: canonicalOrigin,
                repositoryRevision: repositoryRevision,
                operationCID: operationCID,
                stage: .keysStored
            )
            journal = try PLCAccountPreparationJournal(
                requestID: requestID,
                did: did,
                canonicalHandle: handle,
                pdsOrigin: canonicalOrigin,
                repositoryRevision: repositoryRevision,
                operationCID: operationCID,
                signedOperationJSON: operation.canonicalJSON,
                signingKey: try controlReference(keys.signingReference),
                rotationKey: try controlReference(keys.rotationReference),
                publicGenesisCommitCID: nil,
                stage: .keysStored
            )
        } catch {
            throw PLCAccountPreparationError.conflict
        }

        let store = try await openStore(did: did)
        do {
            _ = try await store.installPLCAccountPreparationJournal(journal)
            switch try await intentStore.reservePLCAccountPreparationIntent(intent) {
            case .created:
                return intent
            case let .existing(existing):
                try requireSameInputs(
                    existing,
                    requestID: requestID,
                    handle: handle,
                    pdsOrigin: pdsOrigin,
                    repositoryRevision: repositoryRevision
                )
                return existing
            }
        } catch let error as PLCAccountPreparationError {
            throw error
        } catch let error as PLCAccountPreparationStoreError
            where error == .conflict {
            guard let existing = try await loadIntent(requestID: requestID) else {
                throw PLCAccountPreparationError.conflict
            }
            try requireSameInputs(
                existing,
                requestID: requestID,
                handle: handle,
                pdsOrigin: pdsOrigin,
                repositoryRevision: repositoryRevision
            )
            return existing
        } catch {
            throw PLCAccountPreparationError.unavailable
        }
    }

    private func requireSameInputs(
        _ intent: PLCAccountPreparationIntent,
        requestID: String,
        handle: String,
        pdsOrigin: URL,
        repositoryRevision: String
    ) throws {
        let canonical: String
        do {
            let probe = P256.Signing.PrivateKey()
            canonical = try PLCATProfile.regularOperation(
                handle: handle,
                signingPublicKey: probe.publicKey,
                rotationPublicKeys: [probe.publicKey],
                pdsOrigin: pdsOrigin,
                prev: nil
            ).services["atproto_pds"]!.endpoint
        } catch {
            throw PLCAccountPreparationError.conflict
        }
        guard intent.requestID == requestID,
              intent.canonicalHandle == handle,
              intent.pdsOrigin == canonical,
              intent.repositoryRevision == repositoryRevision else {
            throw PLCAccountPreparationError.conflict
        }
    }

    private func requireJournal(
        store: any PLCAccountPreparationAccountStore,
        intent: PLCAccountPreparationIntent
    ) async throws -> PLCAccountPreparationJournal {
        do {
            guard let journal = try await store.plcAccountPreparationJournal(),
                  journal.requestID == intent.requestID,
                  journal.did == intent.did,
                  journal.canonicalHandle == intent.canonicalHandle,
                  journal.pdsOrigin == intent.pdsOrigin,
                  journal.repositoryRevision == intent.repositoryRevision,
                  journal.operationCID == intent.operationCID else {
                throw PLCAccountPreparationError.conflict
            }
            return journal
        } catch let error as PLCAccountPreparationError {
            throw error
        } catch {
            throw PLCAccountPreparationError.unavailable
        }
    }

    private func loadAndVerifyKeys(
        journal: PLCAccountPreparationJournal
    ) async throws -> ProvisionedAccountKeys {
        do {
            let keys = try await keyProvisioner.resumeProvisioning(
                accountDID: journal.did,
                generation: 1
            )
            guard try controlReference(keys.signingReference) == journal.signingKey,
                  try controlReference(keys.rotationReference) == journal.rotationKey else {
                throw PLCAccountPreparationError.remoteMismatch
            }
            return keys
        } catch let error as PLCAccountPreparationError {
            throw error
        } catch {
            throw PLCAccountPreparationError.unavailable
        }
    }

    private func verifiedOperation(
        journal: PLCAccountPreparationJournal,
        keys: ProvisionedAccountKeys
    ) throws -> PLCSignedOperation {
        do {
            let operation = try PLCOperationCodec.decodeSignedJSON(journal.signedOperationJSON)
            try PLCOperationCodec.verifyGenesis(operation, expectedDID: journal.did)
            guard try operation.cid.string == journal.operationCID,
                  let regular = operation.regular,
                  regular.verificationMethods["atproto"]
                    == P256DIDKey(publicKey: try P256.Signing.PublicKey(
                        x963Representation: keys.signingPublicKey
                    )).value,
                  regular.rotationKeys == [
                    P256DIDKey(publicKey: try P256.Signing.PublicKey(
                        x963Representation: keys.rotationPublicKey
                    )).value,
                  ],
                  regular.alsoKnownAs == ["at://\(journal.canonicalHandle)"],
                  regular.services == [
                    "atproto_pds": PLCService(
                        type: "AtprotoPersonalDataServer",
                        endpoint: journal.pdsOrigin
                    ),
                  ],
                  regular.prev == nil else {
                throw PLCAccountPreparationError.remoteMismatch
            }
            return operation
        } catch let error as PLCAccountPreparationError {
            throw error
        } catch {
            throw PLCAccountPreparationError.remoteMismatch
        }
    }

    private func installOrVerifyPublicGenesis(
        store: any PLCAccountPreparationAccountStore,
        journal: PLCAccountPreparationJournal,
        keys: ProvisionedAccountKeys,
        now: Date
    ) async throws -> PersistedPublicRepositoryGenesis {
        let signingKey: P256.Signing.PrivateKey
        do {
            signingKey = try P256.Signing.PrivateKey(
                rawRepresentation: await keyStore.key(for: keys.signingReference)
            )
        } catch {
            throw PLCAccountPreparationError.unavailable
        }
        do {
            if let existing = try await store.loadPublicRepositoryGenesis(
                did: journal.did,
                signingPublicKey: signingKey.publicKey
            ) {
                guard existing.genesis.revision == journal.repositoryRevision,
                      journal.publicGenesisCommitCID == nil
                        || journal.publicGenesisCommitCID == existing.genesis.commitCID.string else {
                    throw PLCAccountPreparationError.remoteMismatch
                }
                return existing
            }
            let candidate = try PublicRepositoryGenesisCodec.create(
                did: journal.did,
                revision: journal.repositoryRevision,
                signingKey: signingKey
            )
            do {
                return try await store.installPublicRepositoryGenesis(
                    candidate,
                    signingPublicKey: signingKey.publicKey,
                    installedAt: now
                ).persisted
            } catch let error as PublicRepositoryGenesisStoreError
                where error == .conflictingGenesis {
                guard let existing = try await store.loadPublicRepositoryGenesis(
                    did: journal.did,
                    signingPublicKey: signingKey.publicKey
                ), existing.genesis.revision == journal.repositoryRevision else {
                    throw PLCAccountPreparationError.remoteMismatch
                }
                return existing
            }
        } catch let error as PLCAccountPreparationError {
            throw error
        } catch {
            throw PLCAccountPreparationError.unavailable
        }
    }

    private func verifyRemoteIdentity(
        audit: [PLCAuditEntry],
        journal: PLCAccountPreparationJournal,
        operation: PLCSignedOperation,
        keys: ProvisionedAccountKeys,
        publicGenesis: PublicRepositoryGenesis
    ) async throws {
        do {
            guard !audit.isEmpty,
                  audit.allSatisfy({ $0.did == journal.did }),
                  let terminal = audit.last(where: { !$0.nullified }),
                  terminal.cid == journal.operationCID,
                  terminal.operation == operation,
                  terminal.operation.regular != nil,
                  try operation.cid.string == terminal.cid,
                  publicGenesis.did == journal.did,
                  publicGenesis.revision == journal.repositoryRevision,
                  publicGenesis.commitCID.string == journal.publicGenesisCommitCID else {
                throw PLCAccountPreparationError.remoteMismatch
            }
            try PLCOperationCodec.verifyGenesis(terminal.operation, expectedDID: journal.did)
            let state = try await plcClient.fetchState(did: journal.did)
            let regular = try requireRegular(operation)
            guard state.did == journal.did,
                  state.rotationKeys == regular.rotationKeys,
                  state.verificationMethods == regular.verificationMethods,
                  state.alsoKnownAs == regular.alsoKnownAs,
                  state.services == regular.services,
                  keys.signingReference.accountDID == state.did,
                  keys.rotationReference.accountDID == state.did else {
                throw PLCAccountPreparationError.remoteMismatch
            }
        } catch let error as PLCAccountPreparationError {
            throw error
        } catch {
            throw PLCAccountPreparationError.remoteMismatch
        }
    }

    private func advanceJournal(
        _ journal: PLCAccountPreparationJournal,
        store: any PLCAccountPreparationAccountStore,
        to target: PLCAccountPreparationStage,
        publicGenesisCommitCID: String
    ) async throws -> PLCAccountPreparationJournal {
        var current = journal
        while current.stage < target {
            guard let next = PLCAccountPreparationStage(rawValue: current.stage.rawValue + 1) else {
                throw PLCAccountPreparationError.unavailable
            }
            do {
                current = try await store.advancePLCAccountPreparationJournal(
                    requestID: current.requestID,
                    expectedStage: current.stage,
                    to: next,
                    publicGenesisCommitCID: publicGenesisCommitCID
                )
            } catch let error as PLCAccountPreparationStoreError where error == .conflict {
                guard let reloaded = try await store.plcAccountPreparationJournal() else {
                    throw PLCAccountPreparationError.unavailable
                }
                current = reloaded
            } catch {
                throw PLCAccountPreparationError.unavailable
            }
        }
        guard current.stage == target || current.stage > target,
              current.publicGenesisCommitCID == publicGenesisCommitCID else {
            throw PLCAccountPreparationError.remoteMismatch
        }
        return current
    }

    private func advanceIntent(
        _ intent: PLCAccountPreparationIntent,
        to target: PLCAccountPreparationStage
    ) async throws -> PLCAccountPreparationIntent {
        var current = intent
        while current.stage < target {
            guard let next = PLCAccountPreparationStage(rawValue: current.stage.rawValue + 1) else {
                throw PLCAccountPreparationError.unavailable
            }
            do {
                current = try await intentStore.advancePLCAccountPreparationIntent(
                    requestID: current.requestID,
                    expectedStage: current.stage,
                    to: next
                )
            } catch let error as PLCAccountPreparationStoreError where error == .conflict {
                guard let reloaded = try await intentStore.plcAccountPreparationIntent(
                    requestID: current.requestID
                ) else {
                    throw PLCAccountPreparationError.unavailable
                }
                current = reloaded
            } catch {
                throw PLCAccountPreparationError.unavailable
            }
        }
        return current
    }

    private func loadIntent(requestID: String) async throws -> PLCAccountPreparationIntent? {
        do {
            return try await intentStore.plcAccountPreparationIntent(requestID: requestID)
        } catch let error as PLCAccountPreparationStoreError where error == .invalidInput {
            throw PLCAccountPreparationError.conflict
        } catch {
            throw PLCAccountPreparationError.unavailable
        }
    }

    private func openStore(
        did: String
    ) async throws -> any PLCAccountPreparationAccountStore {
        do {
            return try await accountStoreOpener.openPLCAccountPreparationStore(did: did)
        } catch {
            throw PLCAccountPreparationError.unavailable
        }
    }

    private func controlReference(
        _ reference: AccountKeyReference
    ) throws -> AccountControlKeyReference {
        try AccountControlKeyReference(
            purpose: reference.purpose == .signing ? .signing : .rotation,
            generation: reference.generation
        )
    }

    private func requireRegular(
        _ operation: PLCSignedOperation
    ) throws -> PLCSignedRegularOperation {
        guard let regular = operation.regular else {
            throw PLCAccountPreparationError.remoteMismatch
        }
        return regular
    }
}
