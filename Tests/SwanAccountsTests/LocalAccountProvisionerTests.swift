import Crypto
import Foundation
import SQLiteNIO
import SwanPublicRepository
import SwanSQLite
import SwanStorage
import XCTest
@testable import SwanAccounts

final class LocalAccountProvisionerTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let secondDID = "did:plc:bcdefghijklmnopqrstuvwxy"
    private let handle = "alice.example.com"
    private let password = "correct horse battery staple"
    private let revision = "3jzfcijpj2z2a"
    private let installedAt = Date(timeIntervalSince1970: 1_750_000_000.123456)

    func testRecoveryAfterGenesisPersistenceRegistersSameVerifiedCAR() async throws {
        let fixture = try await Fixture(root: temporaryDirectory())
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let failing = fixture.provisioner(
                hooks: .init(afterPublicGenesisInstalled: { throw InjectedFailure.afterGenesis })
            )
            await XCTAssertThrowsAsync(
                try await failing.install(
                    did: did,
                    handle: handle,
                    password: password,
                    revision: revision,
                    now: installedAt
                )
            ) { error in
                XCTAssertEqual(error as? InjectedFailure, .afterGenesis)
            }

            let beforeRetry = try await fixture.directory.account(did: did)
            XCTAssertNil(beforeRetry)
            let maybeFirstGenesis = try await fixture.loadGenesis(did: did)
            let firstGenesis = try XCTUnwrap(maybeFirstGenesis)

            let recovered = try await fixture.provisioner().install(
                did: did,
                handle: handle,
                password: password,
                revision: revision,
                now: installedAt.addingTimeInterval(60)
            )
            XCTAssertTrue(recovered.registrationWasRecovered)
            XCTAssertEqual(recovered.publicGenesis.genesis.car, firstGenesis.genesis.car)
            XCTAssertEqual(recovered.account.status, .active)
            // A crash can leave durable public genesis before control-plane
            // registration. The eventual account creation time remains the
            // registration attempt; immutable genesis-CID binding, not a
            // reused timestamp, provides provenance.
            XCTAssertEqual(
                recovered.account.createdAt,
                installedAt.addingTimeInterval(60)
            )

            let reopened = try await fixture.reopenAccountDatabase()
            let signingKey = try await fixture.keyStore.key(for: try AccountKeyReference(
                accountDID: did,
                purpose: .signing,
                generation: 1
            ))
            let key = try P256.Signing.PrivateKey(rawRepresentation: signingKey)
            let maybeReopenedGenesis = try await reopened.loadPublicRepositoryGenesis(
                did: did,
                signingPublicKey: key.publicKey
            )
            let reopenedGenesis = try XCTUnwrap(maybeReopenedGenesis)
            XCTAssertEqual(reopenedGenesis, firstGenesis)
            try await reopened.close()
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testDuplicateRequiresMatchingActiveKeysGenesisBindingAndPassword() async throws {
        let fixture = try await Fixture(root: temporaryDirectory())
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let installed = try await fixture.provisioner().install(
                did: did,
                handle: handle,
                password: password,
                revision: revision,
                now: installedAt
            )
            let retry = try await fixture.provisioner().install(
                did: did,
                handle: handle,
                password: password,
                revision: revision,
                now: installedAt.addingTimeInterval(10)
            )
            XCTAssertTrue(retry.registrationWasRecovered)
            XCTAssertEqual(retry.account, installed.account)

            await XCTAssertThrowsAsync(
                try await fixture.provisioner().install(
                    did: did,
                    handle: handle,
                    password: "wrong password",
                    revision: revision,
                    now: installedAt.addingTimeInterval(20)
                )
            ) { error in
                XCTAssertEqual(error as? LocalAccountProvisioningError, .conflict)
            }
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testLegacyActiveControlRowIsNeverHealedFromNewGenesis() async throws {
        let fixture = try await Fixture(root: temporaryDirectory())
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let keys = try await fixture.keyProvisioner.provisionInitial(accountDID: did)
            let legacyCreatedAt = installedAt.addingTimeInterval(-10)
            _ = try await fixture.directory.registerProvisionedAccount(
                did: did,
                canonicalHandle: handle,
                password: password,
                signingReference: keys.signingReference,
                rotationReference: keys.rotationReference,
                now: legacyCreatedAt
            )

            for attempt in 0 ..< 2 {
                await XCTAssertThrowsAsync(
                    try await fixture.provisioner().install(
                        did: did,
                        handle: handle,
                        password: password,
                        revision: revision,
                        now: installedAt.addingTimeInterval(Double(attempt))
                    )
                ) { error in
                    XCTAssertEqual(error as? LocalAccountProvisioningError, .conflict)
                }
            }
            let maybeRetainedLegacy = try await fixture.directory.account(did: did)
            let retainedLegacy = try XCTUnwrap(maybeRetainedLegacy)
            XCTAssertEqual(retainedLegacy.createdAt, legacyCreatedAt)
            // A legacy control row has no immutable genesis-CID binding, so
            // the preflight rejects it before creating a public genesis that
            // could later be mistaken for installation provenance.
            let storedGenesis = try await fixture.loadGenesis(did: did)
            XCTAssertNil(storedGenesis)
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testSeparateInstancesAndConnectionsRaceToOneRegistrationWithoutPrivatePersistence() async throws {
        let did = self.did
        let handle = self.handle
        let password = self.password
        let revision = self.revision
        let installedAt = self.installedAt
        let fixture = try await Fixture(root: temporaryDirectory())
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let separateDatabase = try await SQLiteAccountDatabase(
                dataDirectory: fixture.root,
                did: did
            )
            let separateControl = try await SQLiteControlDatabase(dataDirectory: fixture.root)
            let separateHasher = try LibsodiumArgon2idHasher(policy: .interactive)
            let separateDirectory = DurableAccountDirectory(
                store: separateControl,
                passwordHasher: separateHasher,
                verificationExecutor: try Argon2idVerificationExecutor(
                    hasher: separateHasher,
                    maximumConcurrentVerifications: 2,
                    maximumQueuedVerifications: 4
                )
            )
            let first = fixture.provisioner()
            let second = LocalAccountProvisioner(
                directory: separateDirectory,
                publicGenesisStore: separateDatabase,
                keyProvisioner: AccountKeyProvisioner(keyStore: fixture.keyStore),
                keyStore: fixture.keyStore
            )
            // Keep both child tasks alive until both outcomes have been
            // collected. Swift 6.2's Linux concurrency runtime can corrupt
            // an `async let` record when one child completes while the other
            // is still unwinding; explicit tasks preserve the same race
            // while making cleanup and failure collection deterministic.
            let firstTask = Task {
                try await first.install(
                    did: did,
                    handle: handle,
                    password: password,
                    revision: revision,
                    now: installedAt
                )
            }
            let secondTask = Task {
                try await second.install(
                    did: did,
                    handle: handle,
                    password: password,
                    revision: revision,
                    now: installedAt.addingTimeInterval(1)
                )
            }
            let firstOutcome = await firstTask.result
            let secondOutcome = await secondTask.result
            let results = try (firstOutcome.get(), secondOutcome.get())
            XCTAssertEqual(results.0.account.did, did)
            XCTAssertEqual(results.1.account.did, did)
            XCTAssertEqual(
                results.0.account.publicGenesisCommitCID,
                results.1.account.publicGenesisCommitCID
            )
            XCTAssertEqual(
                results.0.account.publicGenesisCommitCID,
                results.0.publicGenesis.genesis.commitCID.string
            )

            let maybeResolved = try await fixture.directory.resolve(handle: handle)
            let resolved = try XCTUnwrap(maybeResolved)
            XCTAssertEqual(resolved.did, did)
            let signingKey = try await fixture.keyStore.key(for: try AccountKeyReference(
                accountDID: did,
                purpose: .signing,
                generation: 1
            ))
            let controlURL = SQLiteLayout.controlDatabase(in: fixture.root)
            let accountURL = SQLiteLayout.accountDatabase(in: fixture.root, did: did)
            try assertNoSecretMaterial(
                in: sqliteArtifacts(for: controlURL) + sqliteArtifacts(for: accountURL),
                password: password,
                privateKey: signingKey
            )
            try await separateDatabase.close()
            try await separateControl.close()
            try await fixture.close()

            try assertNoSecretMaterial(
                in: sqliteArtifacts(for: controlURL) + sqliteArtifacts(for: accountURL),
                password: password,
                privateKey: signingKey
            )

            let raw = try await SQLiteConnection.open(
                storage: .file(path: accountURL.path)
            )
            let permissionedRows = try await raw.query(
                """
                SELECT
                    (SELECT COUNT(*) FROM permissioned_space_records) AS records,
                    (SELECT COUNT(*) FROM permissioned_space_oplog) AS oplog,
                    (SELECT COUNT(*) FROM blob_namespace_references WHERE namespace_kind = 'space') AS space_blobs
                """
            )
            let row = try XCTUnwrap(permissionedRows.first)
            XCTAssertEqual(row.column("records")?.integer, 0)
            XCTAssertEqual(row.column("oplog")?.integer, 0)
            XCTAssertEqual(row.column("space_blobs")?.integer, 0)
            try await raw.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    func testSameHandleAcrossDIDsLeavesAtMostOneActiveControlRegistration() async throws {
        let did = self.did
        let secondDID = self.secondDID
        let handle = self.handle
        let password = self.password
        let revision = self.revision
        let installedAt = self.installedAt
        let fixture = try await Fixture(root: temporaryDirectory())
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        do {
            let secondDatabase = try await SQLiteAccountDatabase(
                dataDirectory: fixture.root,
                did: secondDID
            )
            let secondKeyStore = fixture.keyStore
            let second = LocalAccountProvisioner(
                directory: fixture.directory,
                publicGenesisStore: secondDatabase,
                keyProvisioner: AccountKeyProvisioner(keyStore: secondKeyStore),
                keyStore: secondKeyStore
            )
            let first = fixture.provisioner()
            let firstTask = Task {
                try await first.install(
                    did: did,
                    handle: handle,
                    password: password,
                    revision: revision,
                    now: installedAt
                )
            }
            let secondTask = Task {
                try await second.install(
                    did: secondDID,
                    handle: handle,
                    password: password,
                    revision: revision,
                    now: installedAt
                )
            }
            let firstOutcome = await firstTask.result
            let secondOutcome = await secondTask.result
            let outcomes = [firstOutcome, secondOutcome]
            let successes = outcomes.compactMap { try? $0.get() }
            XCTAssertEqual(successes.count, 1)
            let maybeResolved = try await fixture.directory.resolve(handle: handle)
            let resolved = try XCTUnwrap(maybeResolved)
            XCTAssertEqual(resolved.did, successes[0].account.did)
            try await secondDatabase.close()
            try await fixture.close()
        } catch {
            try? await fixture.close()
            throw error
        }
    }

    private func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory
            .appending(path: "SwanLocalAccountProvisionerTests-\(UUID().uuidString)")
    }
}

private enum InjectedFailure: Error, Equatable {
    case afterGenesis
}

private struct Fixture: Sendable {
    let root: URL
    let database: SQLiteAccountDatabase
    let control: SQLiteControlDatabase
    let keyStore: FileAccountKeyStore
    let keyProvisioner: AccountKeyProvisioner
    let directory: DurableAccountDirectory

    init(root: URL) async throws {
        self.root = root
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o700)],
            ofItemAtPath: root.path
        )
        database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: "did:plc:abcdefghijklmnopqrstuvwx"
        )
        control = try await SQLiteControlDatabase(dataDirectory: root)
        keyStore = try FileAccountKeyStore(
            root: root.appending(path: "keys"),
            configuration: try AccountKeyEncryptionConfiguration(
                activeKeyID: "test-active",
                activeKey: Data(repeating: 42, count: 32)
            )
        )
        keyProvisioner = AccountKeyProvisioner(keyStore: keyStore)
        let hasher = try LibsodiumArgon2idHasher(policy: .interactive)
        directory = DurableAccountDirectory(
            store: control,
            passwordHasher: hasher,
            verificationExecutor: try Argon2idVerificationExecutor(
                hasher: hasher,
                maximumConcurrentVerifications: 2,
                maximumQueuedVerifications: 4
            )
        )
    }

    func provisioner(
        hooks: LocalAccountProvisioningHooks = .init()
    ) -> LocalAccountProvisioner {
        LocalAccountProvisioner(
            directory: directory,
            publicGenesisStore: database,
            keyProvisioner: keyProvisioner,
            keyStore: keyStore,
            testingHooks: hooks
        )
    }

    func loadGenesis(did: String) async throws -> PersistedPublicRepositoryGenesis? {
        let key = try await keyStore.key(for: try AccountKeyReference(
            accountDID: did,
            purpose: .signing,
            generation: 1
        ))
        return try await database.loadPublicRepositoryGenesis(
            did: did,
            signingPublicKey: try P256.Signing.PrivateKey(rawRepresentation: key).publicKey
        )
    }

    func reopenAccountDatabase() async throws -> SQLiteAccountDatabase {
        try await database.close()
        return try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: "did:plc:abcdefghijklmnopqrstuvwx"
        )
    }

    func close() async throws {
        try? await database.close()
        try await control.close()
    }
}

private func XCTAssertThrowsAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ handler: (any Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("expected error", file: file, line: line)
    } catch {
        handler(error)
    }
}

private func sqliteArtifacts(for database: URL) -> [URL] {
    let paths = [database.path, database.path + "-wal", database.path + "-shm"]
    return paths.map(URL.init(fileURLWithPath:)).filter {
        FileManager.default.fileExists(atPath: $0.path)
    }
}

private func assertNoSecretMaterial(
    in files: [URL],
    password: String,
    privateKey: Data
) throws {
    XCTAssertFalse(files.isEmpty)
    for file in files {
        let bytes = try Data(contentsOf: file)
        XCTAssertNil(bytes.range(of: Data(password.utf8)), "raw password in \(file.lastPathComponent)")
        XCTAssertNil(bytes.range(of: privateKey), "private key in \(file.lastPathComponent)")
    }
}
