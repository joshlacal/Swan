import Crypto
import Foundation
import SQLiteNIO
import PetrelCrypto
import PetrelPLC
@testable import SwanAccounts
import SwanCore
import PetrelFirehose
import PetrelRepo
@testable import SwanSQLite
import SwanStorage
import XCTest

final class PLCAccountPreparationServiceTests: XCTestCase {
    func testPreparationBindsExactPLCKeysDIDAndPublicGenesisWithoutActiveAccount() async throws {
        let fixture = try await PreparationFixture()
        defer { fixture.removeFiles() }

        let identity = try await fixture.service().prepare(
            requestID: "request-alpha",
            handle: "Alice.Example.COM",
            pdsOrigin: URL(string: "https://pds.example.com")!,
            repositoryRevision: "3lqby3xuo4k2a"
        )

        let loadedIntent = try await fixture.control
            .plcAccountPreparationIntent(requestID: "request-alpha")
        let intent = try XCTUnwrap(loadedIntent)
        XCTAssertEqual(intent.stage, .submitted)
        XCTAssertEqual(intent.did, identity.did)
        XCTAssertEqual(intent.canonicalHandle, "alice.example.com")
        let activeByDID = try await fixture.control.account(did: identity.did)
        let activeByHandle = try await fixture.control
            .account(canonicalHandle: "alice.example.com")
        XCTAssertNil(activeByDID)
        XCTAssertNil(activeByHandle)

        let account = try await fixture.opener.openPLCAccountPreparationStore(did: identity.did)
        let loadedJournal = try await account.plcAccountPreparationJournal()
        let journal = try XCTUnwrap(loadedJournal)
        XCTAssertEqual(journal.stage, .submitted)
        XCTAssertEqual(journal.publicGenesisCommitCID, identity.publicGenesisCommitCID)
        XCTAssertEqual(journal.signingKey.generation, 1)
        XCTAssertEqual(journal.rotationKey.generation, 1)

        let operation = try SwanPLCGenesisCodec.reconstructGenesis(
            signingDIDKey: journal.operation.signingDIDKey,
            rotationDIDKey: journal.operation.rotationDIDKey,
            canonicalHandle: journal.canonicalHandle,
            pdsOrigin: journal.pdsOrigin,
            signature: journal.operation.signature,
            kemDIDKey: journal.operation.kemDIDKey
        )
        try PLCOperationCodec.verifyGenesis(operation, expectedDID: identity.did)
        XCTAssertEqual(try operation.cid.string, identity.plcOperationCID)
        let kem = try await AccountKEMKeyProvider(keyStore: fixture.keyStore).privateKey(accountDID: identity.did)
        XCTAssertEqual(try AccountKEMKeyProvider.didKey(kem.publicKey), journal.operation.kemDIDKey)
        let rotationData = try await fixture.keyStore.key(for: identity.rotationReference)
        XCTAssertNotEqual(kem.rawRepresentation, rotationData)
        let signingData = try await fixture.keyStore.key(for: identity.signingReference)
        XCTAssertNotEqual(kem.rawRepresentation, signingData)
        let signingKey = try P256.Signing.PrivateKey(rawRepresentation: signingData)
        let loadedGenesis = try await account.loadPublicRepositoryGenesis(
            did: identity.did,
            signingPublicKey: signingKey.publicKey
        )
        let genesis = try XCTUnwrap(loadedGenesis)
        XCTAssertEqual(genesis.genesis.commitCID.string, identity.publicGenesisCommitCID)
        XCTAssertEqual(genesis.genesis.did, identity.did)
        XCTAssertEqual(genesis.genesis.revision, identity.repositoryRevision)
        for value in [
            journal.operation.signingDIDKey,
            journal.operation.rotationDIDKey,
            journal.operation.signature,
        ] {
            XCTAssertFalse(value.lowercased().contains("private"))
            XCTAssertFalse(value.lowercased().contains("password"))
            XCTAssertFalse(value.lowercased().contains("verifier"))
        }
        let submissionCount = await fixture.plc.submitCount()
        XCTAssertEqual(submissionCount, 1)
        try await fixture.close()
    }

    func testExactReplayAndKeyStoreReloadDoNotAdvanceGenerationOrResubmit() async throws {
        let fixture = try await PreparationFixture()
        defer { fixture.removeFiles() }
        let first = try await fixture.service().prepare(
            requestID: "request-replay",
            handle: "replay.example.com",
            pdsOrigin: URL(string: "https://pds.example.com")!,
            repositoryRevision: "3lqby3xuo4k2b"
        )
        let inventoryBefore = try await fixture.keyStore.inventory()
        let reloaded = try FileAccountKeyStore(
            root: fixture.keyRoot,
            configuration: fixture.keyConfiguration
        )
        let second = try await PLCAccountPreparationService(
            intentStore: fixture.control,
            accountStoreOpener: fixture.opener,
            keyStore: reloaded,
            plcClient: fixture.plc
        ).prepare(
            requestID: "request-replay",
            handle: "replay.example.com",
            pdsOrigin: URL(string: "https://pds.example.com")!,
            repositoryRevision: "3lqby3xuo4k2b"
        )
        XCTAssertEqual(first, second)
        XCTAssertEqual(inventoryBefore.totalEnvelopeCount, 3)
        let reloadedInventory = try await reloaded.inventory()
        let submissionCount = await fixture.plc.submitCount()
        XCTAssertEqual(reloadedInventory.totalEnvelopeCount, 3)
        XCTAssertEqual(first.signingReference.generation, 1)
        XCTAssertEqual(first.rotationReference.generation, 1)
        XCTAssertEqual(submissionCount, 1)
        try await fixture.close()
    }

    func testChangedInputForSameRequestFailsClosed() async throws {
        let fixture = try await PreparationFixture()
        defer { fixture.removeFiles() }
        _ = try await fixture.service().prepare(
            requestID: "request-conflict",
            handle: "conflict.example.com",
            pdsOrigin: URL(string: "https://pds.example.com")!,
            repositoryRevision: "3lqby3xuo4k2c"
        )
        for (handle, origin, revision) in [
            ("other.example.com", "https://pds.example.com", "3lqby3xuo4k2c"),
            ("conflict.example.com", "https://other.example.com", "3lqby3xuo4k2c"),
            ("conflict.example.com", "https://pds.example.com", "3lqby3xuo4k2d"),
        ] {
            await XCTAssertThrowsErrorAsync(
                try await fixture.service().prepare(
                    requestID: "request-conflict",
                    handle: handle,
                    pdsOrigin: URL(string: origin)!,
                    repositoryRevision: revision
                )
            ) { error in
                XCTAssertEqual(error as? PLCAccountPreparationError, .conflict)
            }
        }
        let submissionCount = await fixture.plc.submitCount()
        XCTAssertEqual(submissionCount, 1)
        try await fixture.close()
    }

    func testExpectedDIDMismatchFailsBeforeIntentReservationOrPLCSubmission() async throws {
        let fixture = try await PreparationFixture()
        defer { fixture.removeFiles() }

        await XCTAssertThrowsErrorAsync(
            try await fixture.service().prepare(
                requestID: "request-expected-did",
                handle: "expected-did.example.com",
                pdsOrigin: URL(string: "https://pds.example.com")!,
                repositoryRevision: "3lqby3xuo4k2m",
                expectedDID: "did:plc:abcdefghijklmnopqrstuvwx"
            )
        ) { error in
            XCTAssertEqual(
                error as? PLCAccountPreparationError,
                .remoteMismatch
            )
        }
        let intent = try await fixture.control
            .plcAccountPreparationIntent(requestID: "request-expected-did")
        XCTAssertNil(intent)
        let submissionCount = await fixture.plc.submitCount()
        XCTAssertEqual(submissionCount, 0)
        let staged = try await fixture.keyStore.stagedPLCAccountIdentity(
            requestID: "request-expected-did",
            canonicalHandle: "expected-did.example.com",
            pdsOrigin: URL(string: "https://pds.example.com")!,
            repositoryRevision: "3lqby3xuo4k2m"
        )
        XCTAssertNotNil(staged)
        try await fixture.close()
    }

    func testRecoveryAtEveryDurableStageAndAcceptedBeforeLocalStage() async throws {
        for failure in PreparationFailure.allCases {
            let fixture = try await PreparationFixture()
            defer { fixture.removeFiles() }
            let capture = StagedIdentityCapture()
            let failHook: @Sendable () async throws -> Void = { throw failure }
            var hooks = PLCAccountPreparationHooks()
            hooks.afterKeysStaged = { staged in
                try await capture.record(staged)
                if failure == .staged { throw failure }
            }
            switch failure {
            case .staged:
                break
            case .intent:
                hooks.afterIntentReserved = failHook
            case .promoted:
                hooks.afterDIDEnvelopesPromoted = failHook
            case .journalInstalled:
                hooks.afterJournalInstalledBeforeStagingReclaim = failHook
            case .reclaimed:
                hooks.afterStagingReclaimed = failHook
            case .repository:
                hooks.afterRepositoryInstalled = failHook
            case .journalRepositoryInstalled:
                hooks.afterJournalStageAdvanced = { stage in
                    if stage == .repositoryInstalled { throw failure }
                }
            case .journalSubmissionPending:
                hooks.afterJournalStageAdvanced = { stage in
                    if stage == .submissionPending { throw failure }
                }
            case .plcSubmitted:
                hooks.afterPLCSubmitted = failHook
            case .remoteVerified:
                hooks.afterRemoteIdentityVerified = failHook
            case .journalSubmitted:
                hooks.afterJournalStageAdvanced = { stage in
                    if stage == .submitted { throw failure }
                }
            }
            let interrupted = fixture.service(hooks: hooks)
            await XCTAssertThrowsErrorAsync(
                try await interrupted.prepare(
                    requestID: "request-\(failure.rawValue)",
                    handle: "\(failure.rawValue).example.com",
                    pdsOrigin: URL(string: "https://pds.example.com")!,
                    repositoryRevision: "3lqby3xuo4k2e"
                )
            )
            let interruptedIntent = try await fixture.control
                .plcAccountPreparationIntent(requestID: "request-\(failure.rawValue)")
            let retainedStage = try await fixture.keyStore.stagedPLCAccountIdentity(
                requestID: "request-\(failure.rawValue)",
                canonicalHandle: "\(failure.rawValue).example.com",
                pdsOrigin: URL(string: "https://pds.example.com")!,
                repositoryRevision: "3lqby3xuo4k2e"
            )
            let interruptedInventory = try await fixture.keyStore.inventory()
            let interruptedJournalStage: PLCAccountPreparationStage?
            switch failure {
            case .staged, .intent:
                interruptedJournalStage = nil
            default:
                interruptedJournalStage = try await fixture.preparationJournal(
                    did: try XCTUnwrap(interruptedIntent?.did)
                )?.stage
            }
            switch failure {
            case .staged:
                XCTAssertNil(interruptedIntent)
                XCTAssertNotNil(retainedStage)
                XCTAssertEqual(interruptedInventory.totalEnvelopeCount, 0)
            case .intent:
                XCTAssertEqual(interruptedIntent?.stage, .keysStored)
                XCTAssertNotNil(retainedStage)
                XCTAssertEqual(interruptedInventory.totalEnvelopeCount, 0)
            case .promoted:
                XCTAssertEqual(interruptedIntent?.stage, .keysStored)
                XCTAssertNotNil(retainedStage)
                XCTAssertEqual(interruptedInventory.totalEnvelopeCount, 3)
                XCTAssertNil(interruptedJournalStage)
                let account = try await fixture.opener.openPLCAccountPreparationStore(
                    did: try XCTUnwrap(interruptedIntent?.did)
                )
                let journal = try await account.plcAccountPreparationJournal()
                XCTAssertNil(journal)
            case .journalInstalled:
                XCTAssertEqual(interruptedIntent?.stage, .keysStored)
                XCTAssertNotNil(retainedStage)
                XCTAssertEqual(interruptedInventory.totalEnvelopeCount, 3)
                XCTAssertEqual(interruptedJournalStage, .keysStored)
            case .reclaimed, .repository:
                XCTAssertEqual(interruptedIntent?.stage, .keysStored)
                XCTAssertNil(retainedStage)
                XCTAssertEqual(interruptedInventory.totalEnvelopeCount, 3)
                XCTAssertEqual(interruptedJournalStage, .keysStored)
            case .journalRepositoryInstalled:
                XCTAssertEqual(interruptedIntent?.stage, .keysStored)
                XCTAssertNil(retainedStage)
                XCTAssertEqual(interruptedInventory.totalEnvelopeCount, 3)
                XCTAssertEqual(interruptedJournalStage, .repositoryInstalled)
            case .journalSubmissionPending:
                XCTAssertEqual(interruptedIntent?.stage, .repositoryInstalled)
                XCTAssertNil(retainedStage)
                XCTAssertEqual(interruptedInventory.totalEnvelopeCount, 3)
                XCTAssertEqual(interruptedJournalStage, .submissionPending)
            case .plcSubmitted, .remoteVerified:
                XCTAssertEqual(interruptedIntent?.stage, .submissionPending)
                XCTAssertNil(retainedStage)
                XCTAssertEqual(interruptedInventory.totalEnvelopeCount, 3)
                XCTAssertEqual(interruptedJournalStage, .submissionPending)
            case .journalSubmitted:
                XCTAssertEqual(interruptedIntent?.stage, .submissionPending)
                XCTAssertNotNil(interruptedIntent)
                XCTAssertNil(retainedStage)
                XCTAssertEqual(interruptedInventory.totalEnvelopeCount, 3)
                XCTAssertEqual(interruptedJournalStage, .submitted)
            }
            let reloadedKeyStore = try FileAccountKeyStore(
                root: fixture.keyRoot,
                configuration: fixture.keyConfiguration
            )
            let recovered = try await fixture.service(keyStore: reloadedKeyStore).prepare(
                requestID: "request-\(failure.rawValue)",
                handle: "\(failure.rawValue).example.com",
                pdsOrigin: URL(string: "https://pds.example.com")!,
                repositoryRevision: "3lqby3xuo4k2e"
            )
            XCTAssertEqual(recovered.signingReference.generation, 1)
            XCTAssertEqual(recovered.rotationReference.generation, 1)
            let expected = try await capture.requiredSnapshot()
            XCTAssertEqual(recovered.did, expected.did)
            XCTAssertEqual(recovered.plcOperationCID, expected.operationCID)
            let recoveredSigningKey = try await reloadedKeyStore.key(
                for: recovered.signingReference
            )
            let recoveredRotationKey = try await reloadedKeyStore.key(
                for: recovered.rotationReference
            )
            XCTAssertEqual(recoveredSigningKey, expected.signingKey)
            XCTAssertEqual(recoveredRotationKey, expected.rotationKey)
            let recoveredStore = try await fixture.opener.openPLCAccountPreparationStore(
                did: recovered.did
            )
            let loadedRecoveredJournal = try await recoveredStore
                .plcAccountPreparationJournal()
            let recoveredJournal = try XCTUnwrap(loadedRecoveredJournal)
            let recoveredOperation = try SwanPLCGenesisCodec.reconstructGenesis(
                signingDIDKey: recoveredJournal.operation.signingDIDKey,
                rotationDIDKey: recoveredJournal.operation.rotationDIDKey,
                canonicalHandle: recoveredJournal.canonicalHandle,
                pdsOrigin: recoveredJournal.pdsOrigin,
                signature: recoveredJournal.operation.signature,
                kemDIDKey: recoveredJournal.operation.kemDIDKey
            )
            XCTAssertEqual(try recoveredOperation.canonicalJSON, expected.operationJSON)
            let inventory = try await reloadedKeyStore.inventory()
            let submissionCount = await fixture.plc.submitCount()
            let recoveredIntent = try await fixture.control
                .plcAccountPreparationIntent(requestID: "request-\(failure.rawValue)")
            let remainingStage = try await reloadedKeyStore.stagedPLCAccountIdentity(
                requestID: "request-\(failure.rawValue)",
                canonicalHandle: "\(failure.rawValue).example.com",
                pdsOrigin: URL(string: "https://pds.example.com")!,
                repositoryRevision: "3lqby3xuo4k2e"
            )
            XCTAssertEqual(inventory.totalEnvelopeCount, 3)
            XCTAssertEqual(submissionCount, 1)
            XCTAssertEqual(recoveredIntent?.stage, .submitted)
            XCTAssertNil(remainingStage)
            let activeAccount = try await fixture.control.account(did: recovered.did)
            XCTAssertNil(activeAccount)
            try await fixture.close()
        }
    }

    func testPreIntentStageSurvivesRestartWithExactIdentityAndOwnerOnlyEnvelope() async throws {
        let fixture = try await PreparationFixture()
        defer { fixture.removeFiles() }
        let fail: @Sendable () async throws -> Void = { throw PreparationFailure.staged }
        await XCTAssertThrowsErrorAsync(
            try await fixture.service(
                hooks: .init(afterKeysStaged: { _ in try await fail() })
            ).prepare(
                requestID: "request-pre-intent",
                handle: "Pre-Intent.Example.com",
                pdsOrigin: URL(string: "https://pds.example.com")!,
                repositoryRevision: "3lqby3xuo4k2j"
            )
        )

        let preIntent = try await fixture.control
            .plcAccountPreparationIntent(requestID: "request-pre-intent")
        XCTAssertNil(preIntent)
        let preIntentInventory = try await fixture.keyStore.inventory()
        XCTAssertEqual(preIntentInventory.totalEnvelopeCount, 0)
        let loadedStage = try await fixture.keyStore.stagedPLCAccountIdentity(
            requestID: "request-pre-intent",
            canonicalHandle: "pre-intent.example.com",
            pdsOrigin: URL(string: "https://pds.example.com")!,
            repositoryRevision: "3lqby3xuo4k2j"
        )
        let staged = try XCTUnwrap(loadedStage)
        await XCTAssertThrowsErrorAsync(
            try await fixture.keyStore.stagedPLCAccountIdentity(
                requestID: "request-pre-intent",
                canonicalHandle: "changed.example.com",
                pdsOrigin: URL(string: "https://pds.example.com")!,
                repositoryRevision: "3lqby3xuo4k2j"
            )
        )
        let stageURLs = try FileManager.default.contentsOfDirectory(
            at: fixture.keyRoot,
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "plcstage" }
        XCTAssertEqual(stageURLs.count, 1)
        let permissions = try FileManager.default.attributesOfItem(
            atPath: try XCTUnwrap(stageURLs.first).path
        )[.posixPermissions] as? NSNumber
        XCTAssertEqual(permissions?.intValue, 0o600)
        let stagedEnvelopeBytes = try Data(contentsOf: try XCTUnwrap(stageURLs.first))
        let stagedEnvelopeText = try XCTUnwrap(
            String(data: stagedEnvelopeBytes, encoding: .utf8)
        )
        XCTAssertFalse(
            stagedEnvelopeText.contains(staged.signingKey.rawRepresentation.base64EncodedString())
        )
        XCTAssertFalse(
            stagedEnvelopeText.contains(staged.rotationKey.rawRepresentation.base64EncodedString())
        )
        XCTAssertFalse(stagedEnvelopeText.contains(staged.did))
        let rotatingConfiguration = try AccountKeyEncryptionConfiguration(
            activeKeyID: "next-kek",
            activeKey: Data(repeating: 0xB8, count: 32),
            decryptOnlyKeys: ["test-kek": Data(repeating: 0xA7, count: 32)]
        )
        let rotatingStore = try FileAccountKeyStore(
            root: fixture.keyRoot,
            configuration: rotatingConfiguration
        )
        await XCTAssertThrowsErrorAsync(
            try await rotatingStore.migrateAllEnvelopesToActiveKey()
        )

        let restarted = try FileAccountKeyStore(
            root: fixture.keyRoot,
            configuration: fixture.keyConfiguration
        )
        let loadedRestartedStage = try await restarted.stagedPLCAccountIdentity(
            requestID: "request-pre-intent",
            canonicalHandle: "pre-intent.example.com",
            pdsOrigin: URL(string: "https://pds.example.com")!,
            repositoryRevision: "3lqby3xuo4k2j"
        )
        let restartedStage = try XCTUnwrap(loadedRestartedStage)
        XCTAssertEqual(restartedStage.did, staged.did)
        XCTAssertEqual(try restartedStage.operationCID, try staged.operationCID)
        XCTAssertEqual(
            restartedStage.signingKey.rawRepresentation,
            staged.signingKey.rawRepresentation
        )
        XCTAssertEqual(
            restartedStage.rotationKey.rawRepresentation,
            staged.rotationKey.rawRepresentation
        )

        let recovered = try await fixture.service(keyStore: restarted).prepare(
            requestID: "request-pre-intent",
            handle: "pre-intent.example.com",
            pdsOrigin: URL(string: "https://pds.example.com")!,
            repositoryRevision: "3lqby3xuo4k2j"
        )
        XCTAssertEqual(recovered.did, staged.did)
        XCTAssertEqual(recovered.plcOperationCID, try staged.operationCID)
        let remainingStage = try await restarted.stagedPLCAccountIdentity(
            requestID: "request-pre-intent",
            canonicalHandle: "pre-intent.example.com",
            pdsOrigin: URL(string: "https://pds.example.com")!,
            repositoryRevision: "3lqby3xuo4k2j"
        )
        XCTAssertNil(remainingStage)
        let activeAccount = try await fixture.control.account(did: recovered.did)
        XCTAssertNil(activeAccount)
        let migration = try await rotatingStore.migrateAllEnvelopesToActiveKey()
        XCTAssertEqual(migration.migratedEnvelopeCount, 2)
        XCTAssertTrue(migration.inventory.isMigrationComplete)
        try await fixture.close()
    }

    func testConcurrentSameRequestConvergesOnOneVisibleIdentity() async throws {
        let fixture = try await PreparationFixture()
        addTeardownBlock { [fixture] in
            try? await fixture.close()
            fixture.removeFiles()
        }
        let serviceA = fixture.service()
        let serviceB = fixture.service()
        async let a = serviceA.prepare(
            requestID: "request-concurrent",
            handle: "concurrent.example.com",
            pdsOrigin: URL(string: "https://pds.example.com")!,
            repositoryRevision: "3lqby3xuo4k2f"
        )
        async let b = serviceB.prepare(
            requestID: "request-concurrent",
            handle: "concurrent.example.com",
            pdsOrigin: URL(string: "https://pds.example.com")!,
            repositoryRevision: "3lqby3xuo4k2f"
        )
        let identities = try await (a, b)
        XCTAssertEqual(identities.0, identities.1)
        let loadedIntent = try await fixture.control
            .plcAccountPreparationIntent(requestID: "request-concurrent")
        let intent = try XCTUnwrap(loadedIntent)
        XCTAssertEqual(intent.did, identities.0.did)
        let activeAccount = try await fixture.control.account(did: intent.did)
        let submissionCount = await fixture.plc.submitCount()
        XCTAssertNil(activeAccount)
        XCTAssertLessThanOrEqual(submissionCount, 2)
    }

    func testEveryRemoteIdentityMismatchAndInactiveTerminalFailClosedWithoutRegistration() async throws {
        for mode in [
            FakePLC.Mode.mismatchedDID,
            .mismatchedOperationCID,
            .mismatchedSigningKey,
            .mismatchedRotationKey,
            .mismatchedHandle,
            .mismatchedPDSOrigin,
            .inactiveTerminal,
        ] {
            let fixture = try await PreparationFixture(plcMode: mode)
            defer { fixture.removeFiles() }
            await XCTAssertThrowsErrorAsync(
                try await fixture.service().prepare(
                    requestID: "request-\(mode.rawValue)",
                    handle: "\(mode.rawValue).example.com",
                    pdsOrigin: URL(string: "https://pds.example.com")!,
                    repositoryRevision: "3lqby3xuo4k2g"
                )
            ) { error in
                XCTAssertEqual(error as? PLCAccountPreparationError, .remoteMismatch)
            }
            let loadedIntent = try await fixture.control
                .plcAccountPreparationIntent(requestID: "request-\(mode.rawValue)")
            let intent = try XCTUnwrap(loadedIntent)
            let activeAccount = try await fixture.control.account(did: intent.did)
            XCTAssertNil(activeAccount)
            XCTAssertNotEqual(intent.stage, .submitted)
            try await fixture.close()
        }
    }

    func testPLCCallsObserveNoActiveAccountDatabaseWriteTransaction() async throws {
        let fixture = try await PreparationFixture()
        defer { fixture.removeFiles() }
        await fixture.plc.setTransactionProbe {
            !(await fixture.opener.hasActiveWriteTransactionForTesting())
        }
        _ = try await fixture.service().prepare(
            requestID: "request-no-network-in-transaction",
            handle: "transaction.example.com",
            pdsOrigin: URL(string: "https://pds.example.com")!,
            repositoryRevision: "3lqby3xuo4k2h"
        )
        let probesClear = await fixture.plc.allTransactionProbesWereClear()
        XCTAssertTrue(probesClear)
        try await fixture.close()
    }

    func testTamperedPublicGenesisFailsClosedBeforePLCSubmission() async throws {
        let fixture = try await PreparationFixture()
        defer { fixture.removeFiles() }
        let failAfterGenesis: @Sendable () async throws -> Void = {
            throw PreparationFailure.repository
        }
        await XCTAssertThrowsErrorAsync(
            try await fixture.service(
                hooks: .init(afterRepositoryInstalled: failAfterGenesis)
            ).prepare(
                requestID: "request-genesis-tamper",
                handle: "genesis-tamper.example.com",
                pdsOrigin: URL(string: "https://pds.example.com")!,
                repositoryRevision: "3lqby3xuo4k2i"
            )
        )
        let loadedIntent = try await fixture.control
            .plcAccountPreparationIntent(requestID: "request-genesis-tamper")
        let intent = try XCTUnwrap(loadedIntent)
        try await fixture.opener.tamperPublicGenesisCommitCID(did: intent.did)
        await XCTAssertThrowsErrorAsync(
            try await fixture.service().prepare(
                requestID: "request-genesis-tamper",
                handle: "genesis-tamper.example.com",
                pdsOrigin: URL(string: "https://pds.example.com")!,
                repositoryRevision: "3lqby3xuo4k2i"
            )
        )
        let submissionCount = await fixture.plc.submitCount()
        XCTAssertEqual(submissionCount, 0)
        let activeAccount = try await fixture.control.account(did: intent.did)
        XCTAssertNil(activeAccount)
        try await fixture.close()
    }

    func testRejectedActivationTransferDoesNotReplayClosedDatabaseOnRetry() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPLCTransfer-(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let opener = SQLitePLCAccountPreparationStoreOpener(dataDirectory: root)
        let did = "did:plc:zyxwvutsrqponmlkjihgfedc"
        let store = try await opener.openPLCAccountPreparationStore(did: did)
        let database = try XCTUnwrap(store as? SQLiteAccountDatabase)
        let admission = try await opener.takeActivatedAccountAdmission(did: did)
        try await admission.database.close()

        await opener.discardActivatedAccountAdmission(did: did)
        let retried = try await opener.openPLCAccountPreparationStore(did: did)
        let retriedDatabase = try XCTUnwrap(retried as? SQLiteAccountDatabase)
        XCTAssertNotEqual(ObjectIdentifier(database), ObjectIdentifier(retriedDatabase))
        _ = try await retriedDatabase.plcAccountPreparationJournal()
        try await opener.close()
    }
}

final class PLCAccountActivationServiceTests: XCTestCase {
    func testActivationAndExactRetryPreserveGenerationAndPublicCAR() async throws {
        let fixture = try await ActivationFixture(requestID: "activate-success")
        defer { fixture.removeFiles() }
        let store = try await fixture.preparation.opener
            .openPLCAccountPreparationStore(did: fixture.identity.did)
        let signingReference = fixture.identity.signingReference
        let signingMaterial = try await fixture.preparation.keyStore.key(
            for: signingReference
        )
        let signingKey = try P256.Signing.PrivateKey(
            rawRepresentation: signingMaterial
        )
        let loadedGenesis = try await store.loadPublicRepositoryGenesis(
            did: fixture.identity.did,
            signingPublicKey: signingKey.publicKey
        )
        let genesisBefore = try XCTUnwrap(loadedGenesis)
        let inventoryBefore = try await fixture.preparation.keyStore.inventory()
        let activeBefore = try await fixture.preparation.control.account(
            did: fixture.identity.did
        )
        XCTAssertNil(activeBefore)

        let first = try await fixture.activation().activate(
            requestID: "activate-success",
            password: "correct horse battery staple"
        )
        let second = try await fixture.activation().activate(
            requestID: "activate-success",
            password: "correct horse battery staple"
        )

        XCTAssertEqual(first.account, second.account)
        XCTAssertEqual(first.publicGenesis, genesisBefore)
        XCTAssertEqual(second.publicGenesis.genesis.car, genesisBefore.genesis.car)
        XCTAssertEqual(first.account.status, .active)
        XCTAssertEqual(first.account.publicGenesisCommitCID, fixture.identity.publicGenesisCommitCID)
        let inventoryAfter = try await fixture.preparation.keyStore.inventory()
        XCTAssertEqual(inventoryBefore.totalEnvelopeCount, 3)
        XCTAssertEqual(inventoryAfter.totalEnvelopeCount, 3)
        XCTAssertEqual(fixture.identity.signingReference.generation, 1)
        XCTAssertEqual(fixture.identity.rotationReference.generation, 1)
        let verifierCalls = await fixture.verifier.callCount()
        XCTAssertEqual(verifierCalls, 2)
        try await fixture.close()
    }

    func testCrashAfterRegistrationConvergesOnExactRetry() async throws {
        let fixture = try await ActivationFixture(requestID: "activate-crash")
        defer { fixture.removeFiles() }
        let crashing = fixture.activation(
            hooks: .init(afterRegistration: {
                throw PreparationFailure.repository
            })
        )
        await assertActivationError(
            try await crashing.activate(
                requestID: "activate-crash",
                password: "crash-safe-password"
            ),
            expected: .unavailable
        )
        let loadedRegistered = try await fixture.preparation.control.account(
            did: fixture.identity.did
        )
        let registered = try XCTUnwrap(loadedRegistered)
        let recovered = try await fixture.activation().activate(
            requestID: "activate-crash",
            password: "crash-safe-password"
        )
        XCTAssertEqual(recovered.account, registered)
        XCTAssertTrue(recovered.registrationWasRecovered)
        try await fixture.close()
    }

    /// A completed activation wired with the durable lifecycle emitter
    /// enqueues the [#identity, #account(active)] batch in the control store
    /// and the barriered activation #sync in the account outbox.
    func testActivationEmitsLifecycleBatchAndBarrieredHeadSyncWhenEmitterIsWired() async throws {
        let fixture = try await ActivationFixture(requestID: "activate-emitter")
        defer { fixture.removeFiles() }
        let activationTime = Date(timeIntervalSince1970: 1_785_844_800)
        let store = try await fixture.preparation.opener
            .openPLCAccountPreparationStore(did: fixture.identity.did)
        let database = try XCTUnwrap(store as? SQLiteAccountDatabase)
        let emitter = SQLitePublicLifecycleEmitter(
            control: fixture.preparation.control,
            accounts: ActivationFixtureAccountSource(
                accounts: [
                    PublicFirehoseAccountDatabase(
                        did: fixture.identity.did,
                        database: database
                    ),
                ]
            )
        )
        let service = fixture.activation(lifecycleEmitter: emitter)
        let installed = try await service.activate(
            requestID: "activate-emitter",
            password: "emitter-password",
            now: activationTime
        )
        let recovered: LocalAccountInstallation
        do {
            recovered = try await service.activate(
                requestID: "activate-emitter",
                password: "emitter-password",
                now: activationTime.addingTimeInterval(60)
            )
        } catch {
            try await fixture.close()
            throw error
        }
        XCTAssertEqual(recovered.account, installed.account)
        XCTAssertEqual(installed.account.createdAt, activationTime)
        let pendingBatch = try await fixture.preparation.control
            .nextPendingLifecycleBatch(did: fixture.identity.did)
        let batch = try XCTUnwrap(pendingBatch)
        XCTAssertEqual(batch.generation, 1)
        XCTAssertEqual(batch.items.map(\.kind), [.identity, .account])
        XCTAssertEqual(
            batch.items[0].sourceKey,
            PublicFirehoseSourceKey.identity(
                did: fixture.identity.did,
                plcOperationCID: fixture.identity.plcOperationCID
            )
        )
        XCTAssertEqual(
            batch.items[1].sourceKey,
            PublicFirehoseSourceKey.account(
                did: fixture.identity.did,
                operationID: "activate-emitter"
            )
        )
        let identityMaterial = try JSONDecoder().decode(
            PublicFirehoseIdentityMaterial.self,
            from: batch.items[0].payload
        )
        XCTAssertEqual(identityMaterial.did, fixture.identity.did)
        XCTAssertEqual(identityMaterial.handle, "activation.example.org")
        XCTAssertEqual(identityMaterial.time, "2026-08-04T12:00:00.000Z")
        let accountMaterial = try JSONDecoder().decode(
            PublicFirehoseAccountMaterial.self,
            from: batch.items[1].payload
        )
        XCTAssertEqual(accountMaterial.active, true)
        XCTAssertNil(accountMaterial.status)
        XCTAssertEqual(accountMaterial.time, "2026-08-04T12:00:00.000Z")
        let pendingSync = try await database.oldestPendingPublicFirehoseOutbox()
        let sync = try XCTUnwrap(pendingSync)
        XCTAssertEqual(sync.kind, .sync)
        XCTAssertEqual(sync.lifecycleGeneration, batch.generation)
        XCTAssertEqual(
            sync.sourceKey,
            PublicFirehoseSourceKey.syncActivation(
                did: fixture.identity.did,
                operationID: "activate-emitter"
            )
        )
        XCTAssertFalse(sync.carBytes.isEmpty)
        let syncMaterial = try JSONDecoder().decode(
            PublicFirehoseSyncMaterial.self,
            from: sync.payload
        )
        XCTAssertEqual(syncMaterial.did, fixture.identity.did)
        XCTAssertEqual(syncMaterial.rev, fixture.identity.repositoryRevision)
        XCTAssertEqual(
            syncMaterial.commitCID,
            fixture.identity.publicGenesisCommitCID
        )
        XCTAssertEqual(syncMaterial.time, "2026-08-04T12:00:00.000Z")
        try await fixture.close()
    }

    func testBadPasswordAndDuplicateHandleFailWithoutSecondAccount() async throws {
        let badPassword = try await ActivationFixture(requestID: "activate-password")
        defer { badPassword.removeFiles() }
        let installed = try await badPassword.activation().activate(
            requestID: "activate-password",
            password: "first-password"
        )
        await assertActivationError(
            try await badPassword.activation().activate(
                requestID: "activate-password",
                password: "wrong-password"
            ),
            expected: .conflict
        )
        let afterBadPassword = try await badPassword.preparation.control.account(
            did: installed.account.did
        )
        XCTAssertEqual(afterBadPassword, installed.account)
        try await badPassword.close()

        let conflict = try await ActivationFixture(requestID: "activate-handle-conflict")
        defer { conflict.removeFiles() }
        let otherDID = "did:plc:zyxwvutsrqponmlkjihgfedc"
        _ = try await conflict.directory.registerProvisionedAccount(
            did: otherDID,
            canonicalHandle: conflict.identity.canonicalHandle,
            password: "other-password",
            signingReference: try AccountKeyReference(
                accountDID: otherDID,
                purpose: .signing,
                generation: 1
            ),
            rotationReference: try AccountKeyReference(
                accountDID: otherDID,
                purpose: .rotation,
                generation: 1
            )
        )
        await assertActivationError(
            try await conflict.activation().activate(
                requestID: "activate-handle-conflict",
                password: "new-password"
            ),
            expected: .conflict
        )
        let pendingAccount = try await conflict.preparation.control.account(
            did: conflict.identity.did
        )
        let conflictingAccount = try await conflict.preparation.control.account(
            canonicalHandle: conflict.identity.canonicalHandle
        )
        XCTAssertNil(pendingAccount)
        XCTAssertEqual(conflictingAccount?.did, otherDID)
        try await conflict.close()
    }

    func testVerifierPLCTombstoneMutationAndPublicGenesisFailuresNeverActivate() async throws {
        let verifierFailure = try await ActivationFixture(
            requestID: "activate-verifier",
            verifierMode: .failure
        )
        defer { verifierFailure.removeFiles() }
        await assertActivationError(
            try await verifierFailure.activation().activate(
                requestID: "activate-verifier",
                password: "password"
            ),
            expected: .conflict
        )
        let verifierActive = try await verifierFailure.preparation.control.account(
            did: verifierFailure.identity.did
        )
        XCTAssertNil(verifierActive)
        try await verifierFailure.close()

        for (suffix, mode) in [
            ("tombstone", FakePLC.Mode.inactiveTerminal),
            ("handle", FakePLC.Mode.mismatchedHandle),
            ("pds", FakePLC.Mode.mismatchedPDSOrigin),
        ] {
            let fixture = try await ActivationFixture(
                requestID: "activate-plc-\(suffix)"
            )
            defer { fixture.removeFiles() }
            await fixture.preparation.plc.setMode(mode)
            await assertActivationError(
                try await fixture.activation().activate(
                    requestID: "activate-plc-\(suffix)",
                    password: "password"
                ),
                expected: .conflict
            )
            let active = try await fixture.preparation.control.account(
                did: fixture.identity.did
            )
            XCTAssertNil(active)
            try await fixture.close()
        }

        let tampered = try await ActivationFixture(requestID: "activate-genesis")
        defer { tampered.removeFiles() }
        try await tampered.preparation.opener.tamperPublicGenesisCommitCID(
            did: tampered.identity.did
        )
        await assertActivationError(
            try await tampered.activation().activate(
                requestID: "activate-genesis",
                password: "password"
            ),
            expected: .unavailable
        )
        let tamperedActive = try await tampered.preparation.control.account(
            did: tampered.identity.did
        )
        XCTAssertNil(tamperedActive)
        try await tampered.close()
    }

    func testPLCAndHandleNetworkProofRunsOutsideStorageTransactions() async throws {
        let fixture = try await ActivationFixture(requestID: "activate-transactions")
        defer { fixture.removeFiles() }
        let control = fixture.preparation.control
        let opener = fixture.preparation.opener
        await fixture.preparation.plc.setTransactionProbe {
            let controlOpen = await control.hasActiveWriteTransactionForTesting()
            let accountOpen = await opener.hasActiveWriteTransactionForTesting()
            return !controlOpen && !accountOpen
        }
        await fixture.verifier.setTransactionProbe {
            let controlOpen = await control.hasActiveWriteTransactionForTesting()
            let accountOpen = await opener.hasActiveWriteTransactionForTesting()
            return !controlOpen && !accountOpen
        }
        _ = try await fixture.activation().activate(
            requestID: "activate-transactions",
            password: "transaction-password"
        )
        let plcProbesClear = await fixture.preparation.plc
            .allTransactionProbesWereClear()
        let handleProbesClear = await fixture.verifier
            .allTransactionProbesWereClear()
        XCTAssertTrue(plcProbesClear)
        XCTAssertTrue(handleProbesClear)
        try await fixture.close()
    }

    func testUnknownOrUnsubmittedRequestIsOpaqueAndInvisible() async throws {
        let fixture = try await ActivationFixture(requestID: "activate-known")
        defer { fixture.removeFiles() }
        await assertActivationError(
            try await fixture.activation().activate(
                requestID: "unknown-request",
                password: "password"
            ),
            expected: .conflict
        )
        let active = try await fixture.preparation.control.account(
            did: fixture.identity.did
        )
        XCTAssertNil(active)
        try await fixture.close()
    }

    func testSensitiveActivationInputsNeverReachPersistenceOrOpaqueErrors() async throws {
        let fixture = try await ActivationFixture(requestID: "activate-sensitive")
        defer { fixture.removeFiles() }
        let password = "task15-raw-password-sentinel-7f4c"
        let dnsSentinel = "task15-dns-response-sentinel-91ab"
        let httpSentinel = "task15-http-body-sentinel-2de0"
        let signingMaterial = try await fixture.preparation.keyStore.key(
            for: fixture.identity.signingReference
        )
        let rotationMaterial = try await fixture.preparation.keyStore.key(
            for: fixture.identity.rotationReference
        )
        let sensitiveVerifier = ActivationHandleVerifier(mode: .sensitiveFailure)

        do {
            _ = try await fixture.activation(
                handleVerifier: sensitiveVerifier
            ).activate(
                requestID: "activate-sensitive",
                password: password
            )
            XCTFail("expected sensitive verifier failure")
        } catch {
            XCTAssertEqual(
                error as? PLCAccountActivationError,
                .unavailable
            )
            let description = String(describing: error)
            XCTAssertFalse(description.contains(dnsSentinel))
            XCTAssertFalse(description.contains(httpSentinel))
            XCTAssertFalse(description.contains(password))
        }

        _ = try await fixture.activation(
            handleVerifier: ActivationHandleVerifier(mode: .success)
        ).activate(
            requestID: "activate-sensitive",
            password: password
        )
        let forbidden = [
            ("password", Data(password.utf8)),
            ("signing key", signingMaterial),
            ("rotation key", rotationMaterial),
            ("DNS response", Data(dnsSentinel.utf8)),
            ("HTTP body", Data(httpSentinel.utf8)),
        ]
        for file in try regularFiles(under: fixture.preparation.root) {
            let bytes = try Data(contentsOf: file)
            for (name, sentinel) in forbidden {
                XCTAssertNil(
                    bytes.range(of: sentinel),
                    "\(name) leaked to \(file.lastPathComponent)"
                )
            }
        }
        try await fixture.close()
    }

    func testActualDNSSentinelFailureNeverReachesHiddenPersistenceOrErrors() async throws {
        let fixture = try await ActivationFixture(requestID: "activate-dns-sentinel")
        defer { fixture.removeFiles() }
        let dnsSentinel = "did=did:plc:zyxwvutsrqponmlkjihgfedc"
        let verifier = ATProtocolHandleVerifier(
            policy: try .production(),
            dns: ActivationSentinelDNS(rawTXTRecord: Data(dnsSentinel.utf8)),
            http: ActivationUnexpectedHTTP()
        )

        do {
            _ = try await fixture.activation(
                handleVerifier: verifier
            ).activate(
                requestID: "activate-dns-sentinel",
                password: "activation-password"
            )
            XCTFail("expected mismatched DNS handle proof to fail")
        } catch {
            XCTAssertEqual(error as? PLCAccountActivationError, .conflict)
            XCTAssertFalse(String(describing: error).contains(dnsSentinel))
        }

        let active = try await fixture.preparation.control.account(
            did: fixture.identity.did
        )
        XCTAssertNil(active)
        for file in try regularFiles(under: fixture.preparation.root) {
            XCTAssertNil(
                try Data(contentsOf: file).range(of: Data(dnsSentinel.utf8)),
                "raw DNS response leaked to \(file.lastPathComponent)"
            )
        }
        try await fixture.close()
    }

    private func assertActivationError<T>(
        _ expression: @autoclosure () async throws -> T,
        expected: PLCAccountActivationError,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await expression()
            XCTFail("expected activation error", file: file, line: line)
        } catch {
            XCTAssertEqual(
                error as? PLCAccountActivationError,
                expected,
                file: file,
                line: line
            )
        }
    }

    private func regularFiles(under root: URL) throws -> [URL] {
        let keys: [URLResourceKey] = [
            .isRegularFileKey,
            .isSymbolicLinkKey,
        ]
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: keys,
            options: []
        ) else {
            throw SwanError.unavailable("test persistence inventory unavailable")
        }
        var files: [URL] = []
        for case let file as URL in enumerator {
            let values = try file.resourceValues(forKeys: Set(keys))
            guard values.isSymbolicLink != true,
                  values.isRegularFile == true else {
                continue
            }
            files.append(file)
        }
        return files
    }
}

private struct ActivationFixtureAccountSource: PublicFirehoseAccountDatabaseSource {
    let accounts: [PublicFirehoseAccountDatabase]

    func publicFirehoseAccountDatabases() async throws -> [PublicFirehoseAccountDatabase] {
        accounts
    }
}

private final class ActivationFixture: @unchecked Sendable {
    let preparation: PreparationFixture
    let identity: PreparedPLCAccountIdentity
    let directory: DurableAccountDirectory
    let verifier: ActivationHandleVerifier

    init(
        requestID: String,
        verifierMode: ActivationHandleVerifier.Mode = .success
    ) async throws {
        preparation = try await PreparationFixture()
        identity = try await preparation.service().prepare(
            requestID: requestID,
            handle: "activation.example.org",
            pdsOrigin: URL(string: "https://pds.example.org")!,
            repositoryRevision: "3lqby3xuo4k2z"
        )
        let hasher = try LibsodiumArgon2idHasher(policy: .interactive)
        directory = DurableAccountDirectory(
            store: preparation.control,
            passwordHasher: hasher,
            verificationExecutor: try Argon2idVerificationExecutor(
                hasher: hasher,
                maximumConcurrentVerifications: 2,
                maximumQueuedVerifications: 4
            )
        )
        verifier = ActivationHandleVerifier(mode: verifierMode)
    }

    func activation(
        hooks: PLCAccountActivationHooks = .init(),
        lifecycleEmitter: (any PublicLifecycleEventEmitting)? = nil
    ) -> PLCAccountActivationService {
        activation(
            handleVerifier: verifier,
            hooks: hooks,
            lifecycleEmitter: lifecycleEmitter
        )
    }

    func activation(
        handleVerifier: any PLCHandleVerifying,
        hooks: PLCAccountActivationHooks = .init(),
        lifecycleEmitter: (any PublicLifecycleEventEmitting)? = nil
    ) -> PLCAccountActivationService {
        PLCAccountActivationService(
            intentStore: preparation.control,
            accountStoreOpener: preparation.opener,
            keyStore: preparation.keyStore,
            plcClient: preparation.plc,
            handleVerifier: handleVerifier,
            directory: directory,
            hooks: hooks,
            lifecycleEmitter: lifecycleEmitter
        )
    }

    func close() async throws {
        try await preparation.close()
    }

    func removeFiles() {
        preparation.removeFiles()
    }
}

private actor ActivationSentinelDNS: ATHandleDNSResolving {
    let rawTXTRecord: Data

    init(rawTXTRecord: Data) {
        self.rawTXTRecord = rawTXTRecord
    }

    func txtRecords(name _: String) async throws -> [ATHandleTXTRecord] {
        [try ATHandleTXTRecord(bytes: rawTXTRecord)]
    }

    func addresses(host _: String) async throws -> [ATHandleIPAddress] {
        throw ATHandleVerificationError.unavailable
    }
}

private actor ActivationUnexpectedHTTP: ATHandleHTTPFetching {
    func get(
        url _: URL,
        approvedPeers _: Set<ATHandleIPAddress>,
        timeout _: TimeInterval,
        maximumBodyBytes _: Int
    ) async throws -> ATHandleHTTPResponse {
        throw ATHandleVerificationError.unavailable
    }
}

private actor ActivationHandleVerifier: PLCHandleVerifying {
    enum Mode: Sendable {
        case success
        case failure
        case sensitiveFailure
    }

    let mode: Mode
    var calls = 0
    var transactionProbe: (@Sendable () async -> Bool)?
    var transactionResults: [Bool] = []

    init(mode: Mode) {
        self.mode = mode
    }

    func verify(
        plcState: PLCDocumentData,
        expectedDID: String,
        handle: String,
        pdsOrigin: String
    ) async throws -> VerifiedATHandleIdentity {
        calls += 1
        if let transactionProbe {
            transactionResults.append(await transactionProbe())
        }
        if mode == .sensitiveFailure {
            throw SensitiveHandleTransportError(
                dnsResponse: "task15-dns-response-sentinel-91ab",
                httpBody: "task15-http-body-sentinel-2de0"
            )
        }
        guard mode == .success else {
            throw ATHandleVerificationError.verificationFailed
        }
        return .init(
            did: expectedDID,
            canonicalHandle: handle,
            pdsOrigin: pdsOrigin
        )
    }

    func setTransactionProbe(
        _ probe: @escaping @Sendable () async -> Bool
    ) {
        transactionProbe = probe
    }

    func callCount() -> Int { calls }

    func allTransactionProbesWereClear() -> Bool {
        !transactionResults.isEmpty && transactionResults.allSatisfy(\.self)
    }
}

private struct SensitiveHandleTransportError: Error, Sendable,
    CustomStringConvertible
{
    let dnsResponse: String
    let httpBody: String

    var description: String {
        "sensitive handle fixture \(dnsResponse) \(httpBody)"
    }
}

private enum PreparationFailure: String, Error, CaseIterable, Sendable {
    case staged
    case intent
    case promoted
    case journalInstalled = "journal-installed"
    case reclaimed
    case repository
    case journalRepositoryInstalled = "journal-repository-installed"
    case journalSubmissionPending = "journal-submission-pending"
    case plcSubmitted = "plc-submitted"
    case remoteVerified = "remote-verified"
    case journalSubmitted = "journal-submitted"
}

private struct StagedIdentitySnapshot: Sendable {
    let did: String
    let operationCID: String
    let operationJSON: Data
    let signingKey: Data
    let rotationKey: Data
}

private actor StagedIdentityCapture {
    private var snapshot: StagedIdentitySnapshot?

    func record(_ staged: StagedPLCAccountIdentity) throws {
        let operationCID = try staged.operationCID
        let operationJSON = try staged.operation.canonicalJSON
        let candidate = StagedIdentitySnapshot(
            did: staged.did,
            operationCID: operationCID,
            operationJSON: operationJSON,
            signingKey: staged.signingKey.rawRepresentation,
            rotationKey: staged.rotationKey.rawRepresentation
        )
        if let snapshot {
            guard snapshot.did == candidate.did,
                  snapshot.operationCID == candidate.operationCID,
                  snapshot.operationJSON == candidate.operationJSON,
                  snapshot.signingKey == candidate.signingKey,
                  snapshot.rotationKey == candidate.rotationKey else {
                throw PLCAccountPreparationError.conflict
            }
        } else {
            snapshot = candidate
        }
    }

    func requiredSnapshot() throws -> StagedIdentitySnapshot {
        guard let snapshot else { throw PLCAccountPreparationError.unavailable }
        return snapshot
    }
}

private final class PreparationFixture: @unchecked Sendable {
    let root: URL
    let dataRoot: URL
    let keyRoot: URL
    let keyConfiguration: AccountKeyEncryptionConfiguration
    let control: SQLiteControlDatabase
    let opener: TestingPreparationStoreOpener
    let keyStore: FileAccountKeyStore
    let plc: FakePLC

    init(plcMode: FakePLC.Mode = .normal) async throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPLCPreparation-\(UUID().uuidString)")
        dataRoot = root.appending(path: "data")
        keyRoot = root.appending(path: "keys")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        keyConfiguration = try AccountKeyEncryptionConfiguration(
            activeKeyID: "test-kek",
            activeKey: Data(repeating: 0xA7, count: 32)
        )
        control = try await SQLiteControlDatabase(dataDirectory: dataRoot)
        opener = TestingPreparationStoreOpener(dataDirectory: dataRoot)
        keyStore = try FileAccountKeyStore(root: keyRoot, configuration: keyConfiguration)
        plc = FakePLC(mode: plcMode)
    }

    func service(
        keyStore: FileAccountKeyStore? = nil,
        hooks: PLCAccountPreparationHooks = .init()
    ) -> PLCAccountPreparationService {
        PLCAccountPreparationService(
            intentStore: control,
            accountStoreOpener: opener,
            keyStore: keyStore ?? self.keyStore,
            plcClient: plc,
            hooks: hooks
        )
    }

    func close() async throws {
        try await opener.close()
        try await control.close()
    }

    func preparationJournal(
        did: String
    ) async throws -> PLCAccountPreparationJournal? {
        let store = try await opener.openPLCAccountPreparationStore(did: did)
        return try await store.plcAccountPreparationJournal()
    }

    func removeFiles() {
        try? FileManager.default.removeItem(at: root)
    }
}

private actor TestingPreparationStoreOpener: PLCAccountPreparationAccountStoreOpener {
    let dataDirectory: URL
    var databases: [String: SQLiteAccountDatabase] = [:]

    init(dataDirectory: URL) {
        self.dataDirectory = dataDirectory
    }

    func openPLCAccountPreparationStore(
        did: String
    ) async throws -> any PLCAccountPreparationAccountStore {
        if let database = databases[did] { return database }
        let database = try await SQLiteAccountDatabase(dataDirectory: dataDirectory, did: did)
        if let winner = databases[did] {
            try await database.close()
            return winner
        }
        databases[did] = database
        return database
    }

    func hasActiveWriteTransactionForTesting() async -> Bool {
        for database in databases.values {
            if await database.hasActiveWriteTransactionForTesting() {
                return true
            }
        }
        return false
    }

    func tamperPublicGenesisCommitCID(did: String) async throws {
        guard let database = databases[did] else {
            throw SwanError.unavailable("missing test database")
        }
        _ = try await database.connection.query(
            "UPDATE public_repository_genesis SET commit_cid = 'bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
        )
    }

    func close() async throws {
        let values = Array(databases.values)
        databases.removeAll()
        for database in values { try await database.close() }
    }
}

private actor FakePLC: PLCClient {
    enum Mode: String, Sendable {
        case normal
        case mismatchedDID = "did-mismatch"
        case mismatchedOperationCID = "operation-mismatch"
        case mismatchedSigningKey = "signing-mismatch"
        case mismatchedRotationKey = "rotation-mismatch"
        case mismatchedHandle = "handle-mismatch"
        case mismatchedPDSOrigin = "pds-mismatch"
        case inactiveTerminal = "inactive"
    }

    var mode: Mode
    var operations: [String: PLCSignedOperation] = [:]
    var submissions = 0
    var transactionProbe: (@Sendable () async -> Bool)?
    var transactionProbeResults: [Bool] = []

    init(mode: Mode) {
        self.mode = mode
    }

    func setMode(_ mode: Mode) {
        self.mode = mode
    }

    func setTransactionProbe(_ probe: @escaping @Sendable () async -> Bool) {
        transactionProbe = probe
    }

    func submit(did: String, operation: PLCSignedOperation) async throws {
        await probeTransaction()
        if let existing = operations[did], existing != operation {
            throw SwanError.unauthorized("divergent PLC operation")
        }
        operations[did] = operation
        submissions += 1
    }

    func fetchState(did: String) async throws -> PLCDocumentData {
        await probeTransaction()
        guard let operation = operations[did], let regular = operation.regular else {
            throw SwanError.unavailable("missing PLC state")
        }
        var rotationKeys = regular.rotationKeys
        var verificationMethods = regular.verificationMethods
        var aliases = regular.alsoKnownAs
        var services = regular.services
        if mode == .mismatchedRotationKey {
            rotationKeys = ["did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"]
        }
        if mode == .mismatchedSigningKey {
            verificationMethods["atproto"] =
                "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"
        }
        if mode == .mismatchedHandle {
            aliases = ["at://other.example.com"]
        }
        if mode == .mismatchedPDSOrigin {
            services["atproto_pds"] = PLCService(
                type: "AtprotoPersonalDataServer",
                endpoint: "https://other.example.com"
            )
        }
        return PLCDocumentData(
            did: mode == .mismatchedDID
                ? "did:plc:zyxwvutsrqponmlkjihgfedc"
                : did,
            rotationKeys: rotationKeys,
            verificationMethods: verificationMethods,
            alsoKnownAs: aliases,
            services: services
        )
    }

    func fetchAudit(did: String) async throws -> [PLCAuditEntry] {
        guard let result = try await fetchAuditIfPresent(did: did) else {
            throw SwanError.unavailable("missing PLC audit")
        }
        return result
    }

    func fetchAuditIfPresent(did: String) async throws -> [PLCAuditEntry]? {
        await probeTransaction()
        guard let operation = operations[did] else { return nil }
        return [
            PLCAuditEntry(
                did: did,
                operation: operation,
                cid: mode == .mismatchedOperationCID
                    ? "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    : try operation.cid.string,
                nullified: mode == .inactiveTerminal,
                createdAt: "2026-07-27T12:00:00.000Z"
            ),
        ]
    }

    func submitCount() -> Int { submissions }

    func allTransactionProbesWereClear() -> Bool {
        !transactionProbeResults.isEmpty && transactionProbeResults.allSatisfy(\.self)
    }

    private func probeTransaction() async {
        guard let transactionProbe else { return }
        transactionProbeResults.append(await transactionProbe())
    }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ verify: (Error) -> Void = { _ in },
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected error", file: file, line: line)
    } catch {
        verify(error)
    }
}
