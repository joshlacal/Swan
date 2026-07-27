import Crypto
import Foundation
import SQLiteNIO
@testable import SwanAccounts
import SwanCore
import SwanPublicRepository
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
        XCTAssertEqual(journal.operationCID, identity.plcOperationCID)
        XCTAssertEqual(journal.publicGenesisCommitCID, identity.publicGenesisCommitCID)
        XCTAssertEqual(journal.signingKey.generation, 1)
        XCTAssertEqual(journal.rotationKey.generation, 1)

        let operation = try PLCOperationCodec.decodeSignedJSON(journal.signedOperationJSON)
        try PLCOperationCodec.verifyGenesis(operation, expectedDID: identity.did)
        XCTAssertEqual(try operation.cid.string, identity.plcOperationCID)
        let signingData = try await fixture.keyStore.key(for: identity.signingReference)
        let signingKey = try P256.Signing.PrivateKey(rawRepresentation: signingData)
        let loadedGenesis = try await account.loadPublicRepositoryGenesis(
            did: identity.did,
            signingPublicKey: signingKey.publicKey
        )
        let genesis = try XCTUnwrap(loadedGenesis)
        XCTAssertEqual(genesis.genesis.commitCID.string, identity.publicGenesisCommitCID)
        XCTAssertEqual(genesis.genesis.did, identity.did)
        XCTAssertEqual(genesis.genesis.revision, identity.repositoryRevision)
        XCTAssertLessThan(journal.signedOperationJSON.count, 32 * 1_024)
        XCTAssertFalse(String(data: journal.signedOperationJSON, encoding: .utf8)!.contains("PRIVATE"))
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
        XCTAssertEqual(inventoryBefore.totalEnvelopeCount, 2)
        let reloadedInventory = try await reloaded.inventory()
        let submissionCount = await fixture.plc.submitCount()
        XCTAssertEqual(reloadedInventory.totalEnvelopeCount, 2)
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

    func testRecoveryAtEveryDurableStageAndAcceptedBeforeLocalStage() async throws {
        for failure in PreparationFailure.allCases {
            let fixture = try await PreparationFixture()
            defer { fixture.removeFiles() }
            let failHook: @Sendable () async throws -> Void = { throw failure }
            let hooks: PLCAccountPreparationHooks
            switch failure {
            case .intent:
                hooks = .init(afterIntentReserved: failHook)
            case .repository:
                hooks = .init(afterRepositoryInstalled: failHook)
            case .submitted:
                hooks = .init(afterPLCSubmitted: failHook)
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
            let recovered = try await fixture.service().prepare(
                requestID: "request-\(failure.rawValue)",
                handle: "\(failure.rawValue).example.com",
                pdsOrigin: URL(string: "https://pds.example.com")!,
                repositoryRevision: "3lqby3xuo4k2e"
            )
            XCTAssertEqual(recovered.signingReference.generation, 1)
            XCTAssertEqual(recovered.rotationReference.generation, 1)
            let inventory = try await fixture.keyStore.inventory()
            let submissionCount = await fixture.plc.submitCount()
            let recoveredIntent = try await fixture.control
                .plcAccountPreparationIntent(requestID: "request-\(failure.rawValue)")
            XCTAssertEqual(inventory.totalEnvelopeCount, 2)
            XCTAssertEqual(submissionCount, 1)
            XCTAssertEqual(recoveredIntent?.stage, .submitted)
            try await fixture.close()
        }
    }

    func testConcurrentSameRequestConvergesOnOneVisibleIdentity() async throws {
        let fixture = try await PreparationFixture()
        defer { fixture.removeFiles() }
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
        try await fixture.close()
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
}

private enum PreparationFailure: String, Error, CaseIterable, Sendable {
    case intent
    case repository
    case submitted
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
        hooks: PLCAccountPreparationHooks = .init()
    ) -> PLCAccountPreparationService {
        PLCAccountPreparationService(
            intentStore: control,
            accountStoreOpener: opener,
            keyStore: keyStore,
            plcClient: plc,
            hooks: hooks
        )
    }

    func close() async throws {
        try await opener.close()
        try await control.close()
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

    let mode: Mode
    var operations: [String: PLCSignedOperation] = [:]
    var submissions = 0
    var transactionProbe: (@Sendable () async -> Bool)?
    var transactionProbeResults: [Bool] = []

    init(mode: Mode) {
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
