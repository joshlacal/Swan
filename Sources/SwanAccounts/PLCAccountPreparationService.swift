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
    var afterKeysStaged: (@Sendable (StagedPLCAccountIdentity) async throws -> Void)?
    var afterIntentReserved: (@Sendable () async throws -> Void)?
    var afterDIDEnvelopesPromoted: (@Sendable () async throws -> Void)?
    var afterJournalInstalledBeforeStagingReclaim: (@Sendable () async throws -> Void)?
    var afterStagingReclaimed: (@Sendable () async throws -> Void)?
    var afterRepositoryInstalled: (@Sendable () async throws -> Void)?
    var afterPLCSubmitted: (@Sendable () async throws -> Void)?
    var afterRemoteIdentityVerified: (@Sendable () async throws -> Void)?
    var afterJournalStageAdvanced:
        (@Sendable (PLCAccountPreparationStage) async throws -> Void)?
}

/// Creates a durable, remotely authenticated identity package without adding
/// an account registry row. Each await to the PLC client is separated from
/// the bounded storage calls, so no network operation can occur inside either
/// SQLite transaction.
public actor PLCAccountPreparationService {
    private let intentStore: any PLCAccountPreparationIntentStore
    private let accountStoreOpener: any PLCAccountPreparationAccountStoreOpener
    private let keyProvisioner: AccountKeyProvisioner
    private let keyStore: any PLCAccountIdentityStagingKeyStore
    private let plcClient: any PLCClient
    private let hooks: PLCAccountPreparationHooks

    public init(
        intentStore: any PLCAccountPreparationIntentStore,
        accountStoreOpener: any PLCAccountPreparationAccountStoreOpener,
        keyStore: any PLCAccountIdentityStagingKeyStore,
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
        keyStore: any PLCAccountIdentityStagingKeyStore,
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
        let stagedIdentity: StagedPLCAccountIdentity?
        if let existing = try await loadIntent(requestID: requestID) {
            try requireSameInputs(
                existing,
                requestID: requestID,
                handle: handle,
                pdsOrigin: rawPDSOrigin,
                repositoryRevision: repositoryRevision
            )
            intent = existing
            stagedIdentity = try await loadStagedIdentity(
                requestID: requestID,
                handle: handle,
                pdsOrigin: rawPDSOrigin,
                repositoryRevision: repositoryRevision
            )
            if let stagedIdentity {
                try requireStagedIdentity(stagedIdentity, matches: intent)
            }
        } else {
            let staged = try await stageIdentity(
                requestID: requestID,
                handle: handle,
                pdsOrigin: rawPDSOrigin,
                repositoryRevision: repositoryRevision
            )
            try await hooks.afterKeysStaged?(staged)
            intent = try await reserveInitialIntent(staged)
            stagedIdentity = staged
        }

        try await hooks.afterIntentReserved?()
        let store = try await openStore(did: intent.did)
        if let stagedIdentity {
            try await promoteAndJournal(
                stagedIdentity,
                intent: intent,
                store: store
            )
        }
        var journal = try await requireJournal(store: store, intent: intent)
        let keys = try await loadAndVerifyKeys(journal: journal, intent: intent)
        let signedOperation = try verifiedOperation(
            journal: journal,
            intent: intent,
            keys: keys
        )

        let genesis = try await installOrVerifyPublicGenesis(
            store: store,
            journal: journal,
            intent: intent,
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
        try await hooks.afterJournalStageAdvanced?(.repositoryInstalled)
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
        try await hooks.afterJournalStageAdvanced?(.submissionPending)
        currentIntent = try await advanceIntent(currentIntent, to: .submissionPending)

        if let audit = try await plcClient.fetchAuditIfPresent(did: intent.did) {
            try await verifyRemoteIdentity(
                audit: audit,
                journal: journal,
                intent: intent,
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
                intent: intent,
                operation: signedOperation,
                keys: keys,
                publicGenesis: genesis.genesis
            )
        }
        try await hooks.afterRemoteIdentityVerified?()

        journal = try await advanceJournal(
            journal,
            store: store,
            to: .submitted,
            publicGenesisCommitCID: genesis.genesis.commitCID.string
        )
        try await hooks.afterJournalStageAdvanced?(.submitted)
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

    private func stageIdentity(
        requestID: String,
        handle: String,
        pdsOrigin: URL,
        repositoryRevision: String
    ) async throws -> StagedPLCAccountIdentity {
        do {
            return try await keyStore.stagePLCAccountIdentity(
                requestID: requestID,
                canonicalHandle: handle,
                pdsOrigin: pdsOrigin,
                repositoryRevision: repositoryRevision
            )
        } catch {
            throw PLCAccountPreparationError.unavailable
        }
    }

    private func loadStagedIdentity(
        requestID: String,
        handle: String,
        pdsOrigin: URL,
        repositoryRevision: String
    ) async throws -> StagedPLCAccountIdentity? {
        do {
            return try await keyStore.stagedPLCAccountIdentity(
                requestID: requestID,
                canonicalHandle: handle,
                pdsOrigin: pdsOrigin,
                repositoryRevision: repositoryRevision
            )
        } catch {
            throw PLCAccountPreparationError.unavailable
        }
    }

    private func reserveInitialIntent(
        _ staged: StagedPLCAccountIdentity
    ) async throws -> PLCAccountPreparationIntent {
        let intent: PLCAccountPreparationIntent
        do {
            intent = try PLCAccountPreparationIntent(
                requestID: staged.requestID,
                did: staged.did,
                canonicalHandle: staged.canonicalHandle,
                pdsOrigin: staged.pdsOrigin,
                repositoryRevision: staged.repositoryRevision,
                operationCID: staged.operationCID,
                stage: .keysStored
            )
        } catch {
            throw PLCAccountPreparationError.conflict
        }
        do {
            switch try await intentStore.reservePLCAccountPreparationIntent(intent) {
            case .created:
                return intent
            case let .existing(existing):
                try requireStagedIdentity(staged, matches: existing)
                return existing
            }
        } catch {
            throw PLCAccountPreparationError.unavailable
        }
    }

    private func promoteAndJournal(
        _ staged: StagedPLCAccountIdentity,
        intent: PLCAccountPreparationIntent,
        store: any PLCAccountPreparationAccountStore
    ) async throws {
        try requireStagedIdentity(staged, matches: intent)
        let keys: ProvisionedAccountKeys
        do {
            keys = try await keyProvisioner.installInitial(
                accountDID: staged.did,
                signingKey: staged.signingKey,
                rotationKey: staged.rotationKey
            )
            try await hooks.afterDIDEnvelopesPromoted?()
            let journal = try PLCAccountPreparationJournal(
                requestID: staged.requestID,
                canonicalHandle: staged.canonicalHandle,
                pdsOrigin: staged.pdsOrigin,
                repositoryRevision: staged.repositoryRevision,
                operation: try operationFacts(staged.operation),
                signingKey: try controlReference(keys.signingReference),
                rotationKey: try controlReference(keys.rotationReference),
                publicGenesisCommitCID: nil,
                stage: .keysStored
            )
            _ = try await store.installPLCAccountPreparationJournal(journal)
            try await hooks.afterJournalInstalledBeforeStagingReclaim?()
            try await keyStore.reclaimStagedPLCAccountIdentity(
                requestID: staged.requestID,
                expectedDID: staged.did,
                canonicalHandle: staged.canonicalHandle,
                pdsOrigin: URL(string: staged.pdsOrigin)!,
                repositoryRevision: staged.repositoryRevision
            )
            try await hooks.afterStagingReclaimed?()
        } catch let error as PLCAccountPreparationStoreError where error == .conflict {
            throw PLCAccountPreparationError.conflict
        } catch {
            throw PLCAccountPreparationError.unavailable
        }
    }

    private func requireStagedIdentity(
        _ staged: StagedPLCAccountIdentity,
        matches intent: PLCAccountPreparationIntent
    ) throws {
        guard staged.requestID == intent.requestID,
              staged.did == intent.did,
              staged.canonicalHandle == intent.canonicalHandle,
              staged.pdsOrigin == intent.pdsOrigin,
              staged.repositoryRevision == intent.repositoryRevision,
              try staged.operationCID == intent.operationCID else {
            throw PLCAccountPreparationError.conflict
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
                  journal.canonicalHandle == intent.canonicalHandle,
                  journal.pdsOrigin == intent.pdsOrigin,
                  journal.repositoryRevision == intent.repositoryRevision else {
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
        journal: PLCAccountPreparationJournal,
        intent: PLCAccountPreparationIntent
    ) async throws -> ProvisionedAccountKeys {
        do {
            let keys = try await keyProvisioner.resumeProvisioning(
                accountDID: intent.did,
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
        intent: PLCAccountPreparationIntent,
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
                did: intent.did,
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
                did: intent.did,
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
                    did: intent.did,
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
        intent: PLCAccountPreparationIntent,
        operation: PLCSignedOperation,
        keys: ProvisionedAccountKeys,
        publicGenesis: PublicRepositoryGenesis
    ) async throws {
        do {
            guard !audit.isEmpty,
                  audit.allSatisfy({ $0.did == intent.did }),
                  let terminal = audit.last(where: { !$0.nullified }),
                  terminal.cid == intent.operationCID,
                  terminal.operation == operation,
                  terminal.operation.regular != nil,
                  try operation.cid.string == terminal.cid,
                  publicGenesis.did == intent.did,
                  publicGenesis.revision == journal.repositoryRevision,
                  publicGenesis.commitCID.string == journal.publicGenesisCommitCID else {
                throw PLCAccountPreparationError.remoteMismatch
            }
            try PLCOperationCodec.verifyGenesis(terminal.operation, expectedDID: intent.did)
            let state = try await plcClient.fetchState(did: intent.did)
            let regular = try requireRegular(operation)
            guard state.did == intent.did,
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

    private func operationFacts(
        _ operation: PLCSignedOperation
    ) throws -> PLCAccountPreparationOperationFacts {
        guard let regular = operation.regular,
              let signingDIDKey = regular.verificationMethods["atproto"],
              regular.verificationMethods.count == 1,
              regular.rotationKeys.count == 1 else {
            throw PLCAccountPreparationError.remoteMismatch
        }
        return try PLCAccountPreparationOperationFacts(
            signingDIDKey: signingDIDKey,
            rotationDIDKey: regular.rotationKeys[0],
            signature: regular.signature
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
