import Crypto
import Foundation
import PetrelCrypto
import PetrelPLC
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

public struct AccountKEMBackfillResult: Sendable, Equatable {
    public let did: String
    public let operationCID: String
    public let generation: UInt64
    public let publishedNewOperation: Bool
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

    /// Explicitly backfills only an active account still hosted at the expected
    /// PDS. It leaves repository signing and PLC rotation keys unchanged.
    ///
    /// `conflict` is thrown only for facts checked before anything is
    /// submitted (not did:plc, no rotation-key custody, the PDS endpoint moved,
    /// a foreign KEM key, or a PLC head that is not this host's history).
    /// Every other failure, including PLC not accepting a submitted operation,
    /// is `unavailable` or a transport error, so the caller retries it.
    public func backfillKEM(did rawDID: String, expectedPDSOrigin: URL, now: Date = Date()) async throws -> AccountKEMBackfillResult {
        let did = try AccountIdentifiers.validateDID(rawDID)
        let origin = try PLCATProfile.canonicalPDSOrigin(expectedPDSOrigin)
        guard did.hasPrefix("did:plc:"), let account = try await controlStore.account(did: did) else {
            throw PLCAccountRotationError.conflict
        }
        // A deactivated account can be reactivated; it is not ineligible.
        guard account.status == .active else { throw PLCAccountRotationError.unavailable }
        guard let generation = account.signingKey?.generation,
              account.rotationKey?.generation == generation else { throw PLCAccountRotationError.conflict }
        let store = try await accountStoreOpener.openPLCAccountPreparationStore(did: did)
        guard let historyStore = store as? any PublicPLCIdentityHistoryStore else { throw PLCAccountRotationError.unavailable }
        let history = try await ensureHistory(store: store, historyStore: historyStore, account: account, now: now)
        guard let terminal = history.last else { throw PLCAccountRotationError.conflict }
        guard terminal.signingKeyGeneration == generation else {
            // Resolve a pending signing-key rotation through rotate() first;
            // the backfill retries once it has been promoted.
            throw terminal.signingKeyGeneration > generation
                ? PLCAccountRotationError.unavailable : PLCAccountRotationError.conflict
        }
        let operation = try PLCOperationCodec.decodeSignedJSON(terminal.canonicalJSON)
        guard let regular = operation.regular, regular.services["atproto_pds"]?.endpoint == origin else {
            throw PLCAccountRotationError.conflict
        }
        let state = try await plcClient.fetchState(did: did)
        guard state.did == did, state.services["atproto_pds"]?.endpoint == origin else {
            throw PLCAccountRotationError.conflict
        }
        if let published = regular.verificationMethods["atproto_kem"] {
            let key = try await AccountKEMKeyProvider(keyStore: keyStore).privateKey(accountDID: did)
            guard try AccountKEMKeyProvider.didKey(key.publicKey) == published else { throw PLCAccountRotationError.conflict }
            // A persisted KEM operation may be pending after an interrupted
            // submit. Replaying that exact operation is safe and does not
            // allocate a second key or a second history entry.
            let matches = state.verificationMethods == regular.verificationMethods
                && state.rotationKeys == regular.rotationKeys && state.services == regular.services
                && state.alsoKnownAs == regular.alsoKnownAs
            if !matches {
                guard operation.prev != nil else { throw PLCAccountRotationError.conflict }
                try await publishLocalFollowUp(terminal, did: did)
            } else {
                let audit = try await plcClient.fetchAudit(did: did)
                guard let latest = audit.last, !latest.nullified, latest.cid == terminal.cid,
                      latest.operation == operation else { throw PLCAccountRotationError.conflict }
            }
            if operation.prev != nil {
                try await lifecycleEmitter?.emitRotationIdentity(did: did, plcOperationCID: terminal.cid,
                    handle: nil, materialTime: terminal.createdAt, now: now)
            }
            return AccountKEMBackfillResult(did: did, operationCID: terminal.cid, generation: generation, publishedNewOperation: !matches)
        }
        guard state.verificationMethods == regular.verificationMethods,
              state.rotationKeys == regular.rotationKeys, state.services == regular.services,
              state.alsoKnownAs == regular.alsoKnownAs else { throw PLCAccountRotationError.conflict }
        let key = try await AccountKeyProvisioner(keyStore: keyStore).provisionKEM(accountDID: did)
        var methods = regular.verificationMethods
        methods["atproto_kem"] = try AccountKEMKeyProvider.didKey(key.publicKey)
        let rotationKey = try P256.Signing.PrivateKey(rawRepresentation: await keyStore.key(for:
            AccountKeyReference(accountDID: did, purpose: .rotation, generation: generation)))
        let unsigned = try PLCUnsignedRegularOperation(rotationKeys: regular.rotationKeys,
            verificationMethods: methods, alsoKnownAs: regular.alsoKnownAs, services: regular.services, prev: terminal.cid)
        let updated = try PLCOperationCodec.sign(.regular(unsigned), using: rotationKey)
        let proposed = try PublicPLCOperationHistoryEntry(cid: updated.cid.string, previousCID: terminal.cid,
            canonicalJSON: updated.canonicalJSON, createdAt: now, signingKeyGeneration: generation, rotationKeyGeneration: generation)
        let persisted = try await historyStore.installPublicPLCOperation(proposed)
        do {
            try await submitAndVerify(operation: updated, did: did, expectedPrevious: terminal.cid)
        } catch PLCAccountRotationError.conflict {
            // The operation is now local history. A retry replays it, and its
            // pre-submit PLC head check decides whether publication is possible.
            throw PLCAccountRotationError.unavailable
        }
        try await lifecycleEmitter?.emitRotationIdentity(did: did, plcOperationCID: persisted.cid,
            handle: nil, materialTime: persisted.createdAt, now: now)
        return AccountKEMBackfillResult(did: did, operationCID: persisted.cid, generation: generation, publishedNewOperation: true)
    }

    public func rotate(did rawDID: String, now: Date = Date()) async throws -> RotatedPLCAccountIdentity {
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
        // A same-generation follow-up (the KEM backfill operation) is appended
        // before PLC takes it. Never persist a rotation on top of an operation
        // PLC has not accepted: replay it first, or stop before persisting.
        if history.count >= 2,
           history[history.count - 2].signingKeyGeneration == expectedGeneration {
            try await publishLocalFollowUp(terminalEntry, did: did)
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
        let methods = terminalOperation.regular?.verificationMethods ?? [:]
        let rotatedOperation: PLCSignedOperation
        do {
            rotatedOperation = try makeRotation(
                previous: terminalOperation,
                verificationMethods: methods,
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
        let operation = try SwanPLCGenesisCodec.reconstructGenesis(
            signingDIDKey: journal.operation.signingDIDKey,
            rotationDIDKey: journal.operation.rotationDIDKey,
            canonicalHandle: journal.canonicalHandle,
            pdsOrigin: journal.pdsOrigin,
            signature: journal.operation.signature,
                kemDIDKey: journal.operation.kemDIDKey
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
        verificationMethods: [String: String],
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
            verificationMethods: verificationMethods.merging([
                "atproto": P256DIDKey(publicKey: signingPublicKey).value,
            ]) { _, current in current },
            alsoKnownAs: prior.alsoKnownAs,
            services: prior.services,
            prev: previousCID
        )
        return try PLCOperationCodec.sign(.regular(unsigned), using: rotationKey)
    }

    /// Publishes a locally appended operation while PLC's head is still its
    /// parent, or confirms PLC already took it. `conflict` means PLC's head is
    /// elsewhere and is decided before anything is submitted. A submit that
    /// PLC does not take is `unavailable`, so a later call replays the same
    /// stored operation.
    private func publishLocalFollowUp(
        _ entry: PublicPLCOperationHistoryEntry,
        did: String
    ) async throws {
        guard let parent = entry.previousCID else {
            throw PLCAccountRotationError.conflict
        }
        let operation: PLCSignedOperation
        let head: String?
        do {
            operation = try PLCOperationCodec.decodeSignedJSON(entry.canonicalJSON)
            head = try await plcClient.fetchAudit(did: did)
                .last(where: { !$0.nullified })?.cid
        } catch {
            throw PLCAccountRotationError.unavailable
        }
        if head == entry.cid { return }
        guard head == parent else { throw PLCAccountRotationError.conflict }
        do {
            try await submitAndVerify(
                operation: operation,
                did: did,
                expectedPrevious: parent
            )
        } catch PLCAccountRotationError.conflict {
            throw PLCAccountRotationError.unavailable
        }
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
            let head = audit.last(where: { !$0.nullified })
            guard let terminal = head,
                  terminal == audit.last,
                  terminal.operation == operation,
                  terminal.cid == (try operation.cid.string) else {
                // PLC did not take the operation (429, 5xx, timeout) and its
                // head is still the parent: replaying it later can succeed.
                // A head anywhere else is a real conflict.
                if let expectedPrevious, head?.cid == expectedPrevious {
                    throw PLCAccountRotationError.unavailable
                }
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
