import Crypto
import Foundation
import SwanCore
import PetrelFirehose
import PetrelRepo
import PetrelCrypto
import PetrelPLC
@_spi(Testing) import SwanSQLite
import SwanStorage
import XCTest
@testable import SwanAccounts

final class PLCAccountRotationServiceTests: XCTestCase {
    func testKEMBackfillIsIdempotentAndSigningRotationPreservesKEM() async throws {
        let recorder = RecordingLifecycleEmitter()
        let fixture = try await makeFixture(lifecycleEmitter: recorder)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let first = try await fixture.service.backfillKEM(did: fixture.did, expectedPDSOrigin: URL(string: "https://swan.example")!, now: fixture.now)
        XCTAssertTrue(first.publishedNewOperation)
        XCTAssertEqual(first.generation, 1)
        let original = try await AccountKEMKeyProvider(keyStore: fixture.keyStore).privateKey(accountDID: fixture.did)
        let second = try await fixture.service.backfillKEM(did: fixture.did, expectedPDSOrigin: URL(string: "https://swan.example")!, now: fixture.now)
        XCTAssertFalse(second.publishedNewOperation)
        XCTAssertEqual(first.operationCID, second.operationCID)
        let rotated = try await fixture.service.rotate(did: fixture.did, now: fixture.now)
        XCTAssertEqual(rotated.generation, 2)
        XCTAssertEqual(rotated.operation.regular?.verificationMethods["atproto_kem"], try AccountKEMKeyProvider.didKey(original.publicKey))
        let reloaded = try await AccountKEMKeyProvider(keyStore: fixture.keyStore).privateKey(accountDID: fixture.did)
        XCTAssertEqual(original.rawRepresentation, reloaded.rawRepresentation)
        let emissions = await recorder.snapshot()
        XCTAssertEqual(emissions.first?.plcOperationCID, first.operationCID)
        try await fixture.opener.close()
        try await fixture.control.close()
    }

    func testKEMBackfillRejectsDifferentPDSBeforeCreatingLocalKey() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
        do {
            _ = try await fixture.service.backfillKEM(did: fixture.did, expectedPDSOrigin: URL(string: "https://other.example")!, now: fixture.now)
            XCTFail("backfill accepted a different host")
        } catch { XCTAssertEqual(error as? PLCAccountRotationError, .conflict) }
        let key = try await fixture.keyStore.keyIfPresent(for: AccountKEMKeyProvider.reference(accountDID: fixture.did))
        XCTAssertNil(key)
        try await fixture.opener.close()
        try await fixture.control.close()
        } catch {
            try? await fixture.opener.close()
            try? await fixture.control.close()
            throw error
        }
    }

    /// F1: a submit PLC does not take (429, 5xx, timeout) leaves the stored
    /// KEM operation retryable instead of a permanent manual conflict, and
    /// the retry replays that exact operation.
    func testKEMBackfillTreatsUnacceptedSubmitAsRetryableAndReplaysIt() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let origin = URL(string: "https://swan.example")!
            await fixture.plc.rejectNextSubmissions(1)
            do {
                _ = try await fixture.service.backfillKEM(did: fixture.did, expectedPDSOrigin: origin, now: fixture.now)
                XCTFail("an unaccepted submit was reported as published")
            } catch { XCTAssertEqual(error as? PLCAccountRotationError, .unavailable) }
            let pending = try await localHistory(fixture)
            XCTAssertEqual(pending.count, 2)
            let stored = try XCTUnwrap(pending.last)
            let unchanged = await fixture.plc.currentTerminal()
            XCTAssertEqual(try unchanged.cid.string, fixture.genesisCID)

            let replayed = try await fixture.service.backfillKEM(did: fixture.did, expectedPDSOrigin: origin, now: fixture.now)
            XCTAssertTrue(replayed.publishedNewOperation)
            XCTAssertEqual(replayed.operationCID, stored.cid)
            let head = await fixture.plc.currentTerminal()
            XCTAssertEqual(try head.cid.string, stored.cid)
            let history = try await localHistory(fixture)
            XCTAssertEqual(history.count, 2, "the replay must not append a second KEM operation")
            try await fixture.opener.close()
            try await fixture.control.close()
        } catch {
            try? await fixture.opener.close()
            try? await fixture.control.close()
            throw error
        }
    }

    /// F1: rotate() never persists a rotation on top of a KEM operation PLC
    /// has not accepted. It replays that operation first, so a later rotation
    /// is not wedged behind an orphaned parent.
    func testRotationReplaysUnacceptedKEMOperationInsteadOfWedging() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            await fixture.plc.rejectNextSubmissions(1)
            do {
                _ = try await fixture.service.backfillKEM(
                    did: fixture.did, expectedPDSOrigin: URL(string: "https://swan.example")!, now: fixture.now)
                XCTFail("an unaccepted submit was reported as published")
            } catch { XCTAssertEqual(error as? PLCAccountRotationError, .unavailable) }
            let pending = try await localHistory(fixture)
            let stored = try XCTUnwrap(pending.last)

            await fixture.plc.rejectNextSubmissions(1)
            do {
                _ = try await fixture.service.rotate(did: fixture.did, now: fixture.now)
                XCTFail("rotation extended an operation PLC has not accepted")
            } catch { XCTAssertEqual(error as? PLCAccountRotationError, .unavailable) }
            let afterFailure = try await localHistory(fixture)
            XCTAssertEqual(afterFailure.count, 2, "no rotation may be persisted above an unaccepted operation")
            let account = try await fixture.control.account(did: fixture.did)
            XCTAssertEqual(account?.signingKey?.generation, 1)

            let rotated = try await fixture.service.rotate(did: fixture.did, now: fixture.now)
            XCTAssertEqual(rotated.generation, 2)
            XCTAssertEqual(rotated.operation.prev, stored.cid)
            XCTAssertNotNil(rotated.operation.regular?.verificationMethods["atproto_kem"])
            let head = await fixture.plc.currentTerminal()
            XCTAssertEqual(try head.cid.string, try rotated.operation.cid.string)
            try await fixture.opener.close()
            try await fixture.control.close()
        } catch {
            try? await fixture.opener.close()
            try? await fixture.control.close()
            throw error
        }
    }

    /// F1: a pending signing-key rotation defers the backfill; it is not a
    /// reason to mark the account for manual publication.
    func testKEMBackfillDefersBehindPendingRotationInsteadOfMarkingManual() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let origin = URL(string: "https://swan.example")!
            let failure = FailOnceRotationCommit()
            await fixture.control.setBeforeRotationCommitForTesting {
                try await failure.checkpoint()
            }
            do {
                _ = try await fixture.service.rotate(did: fixture.did, now: fixture.now)
                XCTFail("the first atomic control commit should roll back")
            } catch PLCAccountRotationError.unavailable {}
            do {
                _ = try await fixture.service.backfillKEM(did: fixture.did, expectedPDSOrigin: origin, now: fixture.now)
                XCTFail("backfill extended a pending rotation")
            } catch { XCTAssertEqual(error as? PLCAccountRotationError, .unavailable) }

            _ = try await fixture.service.rotate(did: fixture.did, now: fixture.now)
            let published = try await fixture.service.backfillKEM(did: fixture.did, expectedPDSOrigin: origin, now: fixture.now)
            XCTAssertTrue(published.publishedNewOperation)
            XCTAssertEqual(published.generation, 2)
            try await fixture.opener.close()
            try await fixture.control.close()
        } catch {
            try? await fixture.opener.close()
            try? await fixture.control.close()
            throw error
        }
    }

    /// F1: once PLC's head has moved to an operation this host did not write,
    /// the replay and rotate() both stop with a conflict before submitting.
    func testMovedPLCHeadIsAConflictDecidedBeforeSubmitting() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let origin = URL(string: "https://swan.example")!
            await fixture.plc.rejectNextSubmissions(1)
            do {
                _ = try await fixture.service.backfillKEM(did: fixture.did, expectedPDSOrigin: origin, now: fixture.now)
                XCTFail("an unaccepted submit was reported as published")
            } catch { XCTAssertEqual(error as? PLCAccountRotationError, .unavailable) }
            let genesis = await fixture.plc.currentTerminal()
            let parent = try XCTUnwrap(genesis.regular)
            let rotationKey = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 71, count: 32))
            let foreign = try PLCOperationCodec.sign(.regular(try PLCUnsignedRegularOperation(
                rotationKeys: parent.rotationKeys, verificationMethods: parent.verificationMethods,
                alsoKnownAs: ["at://moved.example.com"], services: parent.services,
                prev: fixture.genesisCID)), using: rotationKey)
            await fixture.plc.replaceTerminal(foreign)
            let before = await fixture.plc.submissionCount()

            do {
                _ = try await fixture.service.backfillKEM(did: fixture.did, expectedPDSOrigin: origin, now: fixture.now)
                XCTFail("backfill replayed onto a moved head")
            } catch { XCTAssertEqual(error as? PLCAccountRotationError, .conflict) }
            do {
                _ = try await fixture.service.rotate(did: fixture.did, now: fixture.now)
                XCTFail("rotation extended an operation PLC rejected")
            } catch { XCTAssertEqual(error as? PLCAccountRotationError, .conflict) }
            let after = await fixture.plc.submissionCount()
            XCTAssertEqual(after, before, "a moved head is decided before anything is submitted")
            let history = try await localHistory(fixture)
            XCTAssertEqual(history.count, 2, "no rotation may be persisted above a rejected operation")
            try await fixture.opener.close()
            try await fixture.control.close()
        } catch {
            try? await fixture.opener.close()
            try? await fixture.control.close()
            throw error
        }
    }

    func testRotationPersistsPendingHistoryAndPromotesControlGeneration() async throws {
        let fixture = try await makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let result = try await fixture.service.rotate(
            did: fixture.did,
            now: fixture.now
        )
        XCTAssertEqual(result.generation, 2)
        XCTAssertEqual(result.account.signingKey?.generation, 2)
        XCTAssertEqual(result.account.rotationKey?.generation, 2)
        XCTAssertEqual(result.operation.prev, fixture.genesisCID)

        let reopened = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root, did: fixture.did
        )
        let history = try await reopened.publicPLCOperationHistory()
        XCTAssertEqual(history.count, 2)
        XCTAssertEqual(history.last?.cid, try result.operation.cid.string)
        try await reopened.close()
        try await fixture.opener.close()
        try await fixture.control.close()
    }

    func testRotationAtomicallyEnqueuesIdentityWithControlPromotion() async throws {
        let recorder = RecordingLifecycleEmitter()
        let fixture = try await makeFixture(lifecycleEmitter: recorder)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let rotated = try await fixture.service.rotate(
            did: fixture.did,
            now: fixture.now
        )
        let maybeBatch = try await fixture.control.nextPendingLifecycleBatch(did: fixture.did)
        let batch = try XCTUnwrap(maybeBatch)
        XCTAssertEqual(batch.generation, 1)
        XCTAssertEqual(batch.items.count, 1)
        XCTAssertEqual(batch.items[0].kind, .identity)
        XCTAssertEqual(
            batch.items[0].sourceKey,
            PublicFirehoseSourceKey.identity(
                did: fixture.did,
                plcOperationCID: try rotated.operation.cid.string
            )
        )
        XCTAssertEqual(rotated.account.signingKey?.generation, 2)
        let recorderCount = await recorder.snapshot().count
        XCTAssertEqual(recorderCount, 0)
        try await fixture.opener.close()
        try await fixture.control.close()
    }

    func testPendingRotationRetryUsesPersistedOperationCreationTime() async throws {
        let recorder = RecordingLifecycleEmitter()
        let fixture = try await makeFixture(lifecycleEmitter: recorder)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let failure = FailOnceRotationCommit()
        await fixture.control.setBeforeRotationCommitForTesting {
            try await failure.checkpoint()
        }

        do {
            _ = try await fixture.service.rotate(did: fixture.did, now: fixture.now)
            XCTFail("the first atomic control commit should roll back")
        } catch PLCAccountRotationError.unavailable {}

        let store = try await fixture.opener.openPLCAccountPreparationStore(did: fixture.did)
        let database = try XCTUnwrap(store as? SQLiteAccountDatabase)
        let history = try await database.publicPLCOperationHistory()
        let persistedTime = try XCTUnwrap(history.last?.createdAt)

        _ = try await fixture.service.rotate(
            did: fixture.did,
            now: fixture.now.addingTimeInterval(60)
        )
        let maybeBatch = try await fixture.control.nextPendingLifecycleBatch(did: fixture.did)
        let batch = try XCTUnwrap(maybeBatch)
        XCTAssertEqual(batch.generation, 1)
        let identity = try JSONDecoder().decode(
            PublicFirehoseIdentityMaterial.self,
            from: try XCTUnwrap(batch.items.first).payload
        )
        XCTAssertEqual(identity.time, PublicFirehoseTime.encode(persistedTime))
        let recorderCount = await recorder.snapshot().count
        XCTAssertEqual(recorderCount, 0)
        try await fixture.opener.close()
        try await fixture.control.close()
    }

    func testRotationCausallyOrdersAccountSignedCommitsAroundIdentityAnnouncement() async throws {
        let fixture = try await makeFixture(lifecycleEmitter: RecordingLifecycleEmitter())
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await SQLiteAccountDatabase(
            dataDirectory: fixture.root,
            did: fixture.did
        )
        let firehose = try await SQLiteFirehoseDatabase(dataDirectory: fixture.root)
        defer {
            Task {
                try? await firehose.close()
                try? await database.close()
                try? await fixture.opener.close()
                try? await fixture.control.close()
            }
        }

        let generationOneSigner = try await activeAccountSigner(fixture: fixture)
        XCTAssertEqual(generationOneSigner.generation, 1)
        let loadedGenesisState = try await database.loadPublicRepositoryState()
        let genesisState = try XCTUnwrap(loadedGenesisState)
        let loadedGenesisBytes = try await database.block(for: genesisState.commitCID)
        let genesisBytes = try XCTUnwrap(loadedGenesisBytes)
        _ = try await PublicRepositoryCommitCodec.verify(
            signedCommitBytes: genesisBytes,
            expectedCommitCID: genesisState.commitCID,
            verifier: P256PublicRepositoryCommitVerifier(
                publicKey: generationOneSigner.key.publicKey
            )
        )

        _ = try await fixture.control.enqueueLifecycleEventBatch(
            did: fixture.did,
            operationID: "activation",
            items: [rotationIdentityItem(
                did: fixture.did,
                operationCID: fixture.genesisCID,
                time: fixture.now.addingTimeInterval(-1)
            )],
            now: fixture.now.addingTimeInterval(-1)
        )
        let generationOneCommit = try await applyPublicCommit(
            did: fixture.did,
            recordKey: "before-rotation",
            requestByte: 0x41,
            wallClockMicroseconds: 1_750_000_001_000_000,
            signingGeneration: generationOneSigner.generation,
            signingKey: generationOneSigner.key,
            database: database,
            control: fixture.control
        )

        let rotated = try await fixture.service.rotate(did: fixture.did, now: fixture.now)
        let generationTwoSigner = try await activeAccountSigner(fixture: fixture)
        XCTAssertEqual(generationTwoSigner.generation, 2)
        let generationTwoCommit = try await applyPublicCommit(
            did: fixture.did,
            recordKey: "after-rotation",
            requestByte: 0x42,
            wallClockMicroseconds: 1_750_000_002_000_000,
            signingGeneration: generationTwoSigner.generation,
            signingKey: generationTwoSigner.key,
            database: database,
            control: fixture.control
        )

        let sequencer = PublicFirehoseSequencer(
            accountSource: RotationFirehoseAccountSource(
                did: fixture.did,
                database: database
            ),
            control: fixture.control,
            firehose: firehose
        )
        let drained = try await sequencer.drainAll(
            now: Date(timeIntervalSince1970: 2_000_000_000)
        )
        XCTAssertEqual(drained, 4)
        let events = try await firehose.events(after: 0, limit: 10, maximumBytes: 4 * FirehoseFrameLimits.maximumFrameBytes)
        XCTAssertEqual(events.map(\.kind), [.identity, .commit, .identity, .commit])
        XCTAssertEqual(
            events.map(\.sourceKey),
            [
                PublicFirehoseSourceKey.identity(
                    did: fixture.did,
                    plcOperationCID: fixture.genesisCID
                ),
                PublicFirehoseSourceKey.commit(
                    did: fixture.did,
                    commitCID: generationOneCommit.commitCID.string
                ),
                PublicFirehoseSourceKey.identity(
                    did: fixture.did,
                    plcOperationCID: try rotated.operation.cid.string
                ),
                PublicFirehoseSourceKey.commit(
                    did: fixture.did,
                    commitCID: generationTwoCommit.commitCID.string
                ),
            ]
        )
        _ = try await PublicRepositoryCommitCodec.verify(
            signedCommitBytes: generationOneCommit.signedCommitBytes,
            expectedCommitCID: generationOneCommit.commitCID,
            verifier: P256PublicRepositoryCommitVerifier(
                publicKey: generationOneSigner.key.publicKey
            )
        )
        _ = try await PublicRepositoryCommitCodec.verify(
            signedCommitBytes: generationTwoCommit.signedCommitBytes,
            expectedCommitCID: generationTwoCommit.commitCID,
            verifier: P256PublicRepositoryCommitVerifier(
                publicKey: generationTwoSigner.key.publicKey
            )
        )
    }

    private func activeAccountSigner(
        fixture: RotationFixture
    ) async throws -> (generation: UInt64, key: P256.Signing.PrivateKey) {
        let loadedAccount = try await fixture.control.account(did: fixture.did)
        let account = try XCTUnwrap(loadedAccount)
        let generation = try XCTUnwrap(account.signingKey?.generation)
        let reference = try AccountKeyReference(
            accountDID: fixture.did,
            purpose: .signing,
            generation: generation
        )
        let key = try P256.Signing.PrivateKey(
            rawRepresentation: try await fixture.keyStore.key(for: reference)
        )
        return (generation, key)
    }

    private func rotationIdentityItem(
        did: String,
        operationCID: String,
        time: Date
    ) throws -> LifecycleEventItem {
        LifecycleEventItem(
            sourceKey: PublicFirehoseSourceKey.identity(
                did: did,
                plcOperationCID: operationCID
            ),
            kind: .identity,
            payload: try JSONEncoder().encode(
                PublicFirehoseIdentityMaterial(
                    did: did,
                    handle: "alice.example.com",
                    time: PublicFirehoseTime.encode(time)
                )
            ),
            carBytes: nil
        )
    }

    private func applyPublicCommit(
        did: String,
        recordKey: String,
        requestByte: UInt8,
        wallClockMicroseconds: UInt64,
        signingGeneration: UInt64,
        signingKey: P256.Signing.PrivateKey,
        database: SQLiteAccountDatabase,
        control: SQLiteControlDatabase
    ) async throws -> PreparedPublicRepositorySignedCommit {
        let loadedCurrent = try await database.loadPublicRepositoryState()
        let current = try XCTUnwrap(loadedCurrent)
        let request = try PublicRepositoryMutationRequest(
            id: "rotation-ordering-\(recordKey)",
            canonicalDigest: Data(repeating: requestByte, count: 32),
            baseCommitCID: current.commitCID
        )
        let reservation: PublicRepositoryMutationReservation
        switch try await database.reservePublicRepositoryRevision(
            request,
            wallClockMicroseconds: wallClockMicroseconds
        ) {
        case let .reserved(value):
            reservation = value
        case .committed:
            throw SwanError.conflict(expected: 0, actual: 1)
        }
        let prepared = try await PublicRepositoryEngine.apply(
            repositoryDID: did,
            currentState: current,
            blocks: database,
            revision: reservation.nextRevision,
            batch: try PublicRepositoryWriteBatch(
                writes: [.create(
                    path: try PublicRepositoryPath(
                        collection: "app.bsky.feed.post",
                        recordKey: recordKey
                    ),
                    record: PublicRecord([
                        "$type": .string("app.bsky.feed.post"),
                        "text": .string(recordKey),
                    ])
                )],
                expectedCommitCID: current.commitCID
            ),
            signer: P256PublicRepositoryCommitSigner(privateKey: signingKey),
            signingGeneration: signingGeneration
        )
        let fence = PublicFirehoseCommitFence(control: control)
        _ = try await fence.apply(
            did: did,
            signingGeneration: signingGeneration
        ) { context in
            try await database.applyPublicRepositoryMutation(
                reservation: reservation,
                prepared: prepared,
                firehose: context
            )
        }
        return prepared.signedCommit
    }

    private struct RotationFixture {
        let root: URL
        let did: String
        let now: Date
        let genesisCID: String
        let service: PLCAccountRotationService
        let control: SQLiteControlDatabase
        let opener: SQLitePLCAccountPreparationStoreOpener
        let keyStore: FileAccountKeyStore
        let plc: RotatingPLCFixture
    }

    private func makeFixture(
        lifecycleEmitter: (any PublicLifecycleEventEmitting)? = nil
    ) async throws -> RotationFixture {
        let root = try temporaryDirectory()
        let didHandle = "alice.example.com"
        let pdsOrigin = "https://swan.example"
        let signing = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 67, count: 32)
        )
        let rotation = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 71, count: 32)
        )
        let genesisUnsigned = try PLCATProfile.regularOperation(
            handle: didHandle,
            signingPublicKey: signing.publicKey,
            rotationPublicKeys: [rotation.publicKey],
            pdsOrigin: URL(string: pdsOrigin)!,
            prev: nil
        )
        let genesis = try PLCOperationCodec.sign(.regular(genesisUnsigned), using: rotation)
        let did = try PLCOperationCodec.genesisDID(for: genesis)
        let keyRoot = root.appending(path: "keys")
        let keyStore = try FileAccountKeyStore(
            root: keyRoot,
            configuration: try AccountKeyEncryptionConfiguration(
                activeKeyID: "test",
                activeKey: Data(repeating: 73, count: 32)
            )
        )
        let keyProvisioner = AccountKeyProvisioner(keyStore: keyStore)
        _ = try await keyProvisioner.installInitial(
            accountDID: did,
            signingKey: signing,
            rotationKey: rotation
        )

        let accountDatabase = try await SQLiteAccountDatabase(
            dataDirectory: root, did: did
        )
        let repositoryGenesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: "3jzfcijpj2z2a",
            signingKey: signing
        )
        _ = try await accountDatabase.installPublicRepositoryGenesis(
            repositoryGenesis,
            signingPublicKey: signing.publicKey,
            installedAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
        let journal = try PLCAccountPreparationJournal(
            requestID: "rotation-service",
            canonicalHandle: didHandle,
            pdsOrigin: pdsOrigin,
            repositoryRevision: "3jzfcijpj2z2a",
            operation: try PLCAccountPreparationOperationFacts(
                signingDIDKey: try XCTUnwrap(
                    genesis.regular?.verificationMethods["atproto"]
                ),
                rotationDIDKey: try XCTUnwrap(genesis.regular?.rotationKeys.first),
                signature: try XCTUnwrap(genesis.regular?.signature)
            ),
            signingKey: try AccountControlKeyReference(
                purpose: .signing, generation: 1
            ),
            rotationKey: try AccountControlKeyReference(
                purpose: .rotation, generation: 1
            ),
            publicGenesisCommitCID: nil,
            stage: .keysStored
        )
        _ = try await accountDatabase.installPLCAccountPreparationJournal(journal)
        _ = try await accountDatabase.advancePLCAccountPreparationJournal(
            requestID: journal.requestID,
            expectedStage: .keysStored,
            to: .repositoryInstalled,
            publicGenesisCommitCID: repositoryGenesis.commitCID.string
        )
        _ = try await accountDatabase.advancePLCAccountPreparationJournal(
            requestID: journal.requestID,
            expectedStage: .repositoryInstalled,
            to: .submissionPending,
            publicGenesisCommitCID: nil
        )
        _ = try await accountDatabase.advancePLCAccountPreparationJournal(
            requestID: journal.requestID,
            expectedStage: .submissionPending,
            to: .submitted,
            publicGenesisCommitCID: nil
        )
        try await accountDatabase.close()

        let control = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await control.createAccount(
            try AccountControlRegistration(
                did: did,
                canonicalHandle: didHandle,
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: try AccountControlKeyReference(
                    purpose: .signing, generation: 1
                ),
                rotationKey: try AccountControlKeyReference(
                    purpose: .rotation, generation: 1
                ),
                publicGenesisCommitCID: repositoryGenesis.commitCID.string,
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )

        let plc = RotatingPLCFixture(did: did, terminal: genesis)
        let opener = SQLitePLCAccountPreparationStoreOpener(dataDirectory: root)
        let service = PLCAccountRotationService(
            controlStore: control,
            accountStoreOpener: opener,
            keyStore: keyStore,
            plcClient: plc,
            lifecycleEmitter: lifecycleEmitter
        )
        return RotationFixture(
            root: root,
            did: did,
            now: Date(timeIntervalSince1970: 1_750_000_001.123_456_7),
            genesisCID: try genesis.cid.string,
            service: service,
            control: control,
            opener: opener,
            keyStore: keyStore,
            plc: plc
        )
    }

    private func localHistory(_ fixture: RotationFixture) async throws -> [PublicPLCOperationHistoryEntry] {
        let store = try await fixture.opener.openPLCAccountPreparationStore(did: fixture.did)
        let database = try XCTUnwrap(store as? SQLiteAccountDatabase)
        return try await database.publicPLCOperationHistory()
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPLCAccountRotationTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }
}

private struct RotationFirehoseAccountSource: PublicFirehoseAccountDatabaseSource {
    let did: String
    let database: SQLiteAccountDatabase

    func publicFirehoseAccountDatabases() async throws -> [PublicFirehoseAccountDatabase] {
        [PublicFirehoseAccountDatabase(did: did, database: database)]
    }
}

private enum RotationEmissionFailure: Error {
    case intentional
}

private actor FailOnceRotationCommit {
    private var shouldFail = true

    func checkpoint() throws {
        if shouldFail {
            shouldFail = false
            throw RotationEmissionFailure.intentional
        }
    }
}

private struct RecordedRotation: Sendable {
    let did: String
    let plcOperationCID: String
    let materialTime: Date
    let now: Date
}

private actor RecordingLifecycleEmitter: PublicLifecycleEventEmitting {
    private var rotations: [RecordedRotation] = []
    private var shouldFailRotation: Bool

    init(failFirstRotation: Bool = false) {
        shouldFailRotation = failFirstRotation
    }

    func emitActivation(
        did: String, operationID: String, plcOperationCID: String,
        handle: String?, materialTime: Date, now: Date
    ) async throws {}

    func emitRotationIdentity(
        did: String, plcOperationCID: String, handle: String?,
        materialTime: Date, now: Date
    ) async throws {
        rotations.append(
            RecordedRotation(
                did: did,
                plcOperationCID: plcOperationCID,
                materialTime: materialTime,
                now: now
            )
        )
        if shouldFailRotation {
            shouldFailRotation = false
            throw RotationEmissionFailure.intentional
        }
    }

    func emitReactivationSync(did: String, operationID: String, now: Date) async throws {}

    func emitManualSync(did: String, requestUUID: String, now: Date) async throws {}

    func snapshot() -> [RecordedRotation] {
        rotations
    }
}

private actor RotatingPLCFixture: PLCClient {
    private let did: String
    private var terminal: PLCSignedOperation
    private var rejectedSubmissions = 0
    private var submissions = 0

    init(did: String, terminal: PLCSignedOperation) {
        self.did = did
        self.terminal = terminal
    }

    /// PLC answers 429/5xx or times out: nothing is accepted.
    func rejectNextSubmissions(_ count: Int) { rejectedSubmissions = count }
    /// Another rotation-key holder moves the head.
    func replaceTerminal(_ operation: PLCSignedOperation) { terminal = operation }
    func currentTerminal() -> PLCSignedOperation { terminal }
    func submissionCount() -> Int { submissions }

    func submit(did: String, operation: PLCSignedOperation) async throws {
        submissions += 1
        if rejectedSubmissions > 0 {
            rejectedSubmissions -= 1
            throw SwanError.unavailable("PLC fixture rate limited")
        }
        guard did == self.did,
              operation.prev == (try terminal.cid.string),
              let parent = terminal.regular else {
            throw SwanError.conflict(expected: 0, actual: 1)
        }
        _ = try PLCOperationCodec.verify(
            operation,
            authorizedRotationKeys: parent.rotationKeys
        )
        terminal = operation
    }

    func fetchState(did: String) async throws -> PLCDocumentData {
        guard did == self.did, let regular = terminal.regular else {
            throw SwanError.unavailable("PLC fixture state is unavailable")
        }
        return PLCDocumentData(
            did: did,
            rotationKeys: regular.rotationKeys,
            verificationMethods: regular.verificationMethods,
            alsoKnownAs: regular.alsoKnownAs,
            services: regular.services
        )
    }

    func fetchAudit(did: String) async throws -> [PLCAuditEntry] {
        guard did == self.did else {
            throw SwanError.unavailable("PLC fixture audit is unavailable")
        }
        return [
            PLCAuditEntry(
                did: did,
                operation: terminal,
                cid: try terminal.cid.string,
                nullified: false,
                createdAt: "2026-07-28T00:00:00Z"
            ),
        ]
    }
}
