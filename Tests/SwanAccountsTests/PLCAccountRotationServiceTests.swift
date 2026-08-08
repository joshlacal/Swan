import Crypto
import Foundation
import SwanCore
import SwanPublicRepository
import SwanSQLite
import SwanStorage
import XCTest
@testable import SwanAccounts

final class PLCAccountRotationServiceTests: XCTestCase {
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
        XCTAssertEqual(result.operation.prev, try fixture.genesisCID)

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

    func testRotationEmitsIdentityKeyedOnConfirmedOperationBeforePromotion() async throws {
        let recorder = RecordingLifecycleEmitter()
        let fixture = try await makeFixture(lifecycleEmitter: recorder)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let rotated = try await fixture.service.rotate(
            did: fixture.did,
            now: fixture.now
        )
        let emitted = await recorder.snapshot()
        XCTAssertEqual(emitted.count, 1)
        XCTAssertEqual(emitted[0].did, fixture.did)
        XCTAssertEqual(emitted[0].plcOperationCID, try rotated.operation.cid.string)
        try await fixture.opener.close()
        try await fixture.control.close()
    }

    func testPendingRotationRetryUsesPersistedOperationCreationTime() async throws {
        let recorder = RecordingLifecycleEmitter(failFirstRotation: true)
        let fixture = try await makeFixture(lifecycleEmitter: recorder)
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        do {
            _ = try await fixture.service.rotate(did: fixture.did, now: fixture.now)
            XCTFail("the first lifecycle emission should fail after history is durable")
        } catch RotationEmissionFailure.intentional {}

        let store = try await fixture.opener.openPLCAccountPreparationStore(did: fixture.did)
        let database = try XCTUnwrap(store as? SQLiteAccountDatabase)
        let history = try await database.publicPLCOperationHistory()
        let persistedTime = try XCTUnwrap(history.last?.createdAt)

        _ = try await fixture.service.rotate(
            did: fixture.did,
            now: fixture.now.addingTimeInterval(60)
        )
        let emitted = await recorder.snapshot()
        XCTAssertEqual(emitted.map(\.materialTime), [persistedTime, persistedTime])
        XCTAssertEqual(emitted.map(\.now), [fixture.now, fixture.now.addingTimeInterval(60)])
        try await fixture.opener.close()
        try await fixture.control.close()
    }

    private struct RotationFixture {
        let root: URL
        let did: String
        let now: Date
        let genesisCID: String
        let service: PLCAccountRotationService
        let control: SQLiteControlDatabase
        let opener: SQLitePLCAccountPreparationStoreOpener
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
        let repositoryKey = P256.Signing.PrivateKey()
        let repositoryGenesis = try PublicRepositoryGenesisCodec.create(
            did: did,
            revision: "3jzfcijpj2z2a",
            signingKey: repositoryKey
        )
        _ = try await accountDatabase.installPublicRepositoryGenesis(
            repositoryGenesis,
            signingPublicKey: repositoryKey.publicKey,
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
            opener: opener
        )
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

private enum RotationEmissionFailure: Error {
    case intentional
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

    init(did: String, terminal: PLCSignedOperation) {
        self.did = did
        self.terminal = terminal
    }

    func submit(did: String, operation: PLCSignedOperation) async throws {
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
