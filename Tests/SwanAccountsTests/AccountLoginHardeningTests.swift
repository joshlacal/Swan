import Dispatch
import Foundation
import SQLiteNIO
import SwanCore
import SwanSQLite
import SwanStorage
import XCTest
@testable import SwanAccounts

final class AccountLoginHardeningTests: XCTestCase {
    fileprivate static let knownDID = "did:plc:abcdefghijklmnopqrstuvwx"
    fileprivate static let missingDID = "did:plc:bcdefghijklmnopqrstuvwxy"
    fileprivate static let malformedDID = "did:plc:zyxwvutsrqponmlkjihgfedc"
    fileprivate static let realVerifier =
        "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
    fileprivate static let dummyVerifier =
        "$argon2id$v=19$m=65536,t=2,p=1$bcdefghijklmnopqrstuvw$BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
    fileprivate static let parameterVariantVerifier =
        "$argon2id$v=19$m=65536,t=3,p=1$cdefghijklmnopqrstuvwx$CDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs"

    func testRejectedAccountShapesEachPerformExactlyOneArgon2Verification() async throws {
        let recorder = LoginVerificationRecorder()
        let executor = try Argon2idVerificationExecutor(
            maximumConcurrentVerifications: 1,
            maximumQueuedVerifications: 0
        ) { _, verifier in
            recorder.record(verifier)
            return false
        }
        let directory = DurableAccountDirectory(
            store: LoginShapeAccountStore(),
            passwordHasher: LoginDummyHasher(),
            verificationExecutor: executor
        )

        let cases: [(String, String)] = [
            ("known-wrong.example.com", Self.realVerifier),
            ("unknown.example.com", Self.dummyVerifier),
            ("inactive.example.com", Self.dummyVerifier),
            ("missing.example.com", Self.dummyVerifier),
            ("malformed-verifier.example.com", Self.dummyVerifier),
            ("parameter-variant.example.com", Self.dummyVerifier),
            ("not a handle", Self.dummyVerifier),
        ]
        for (handle, expectedVerifier) in cases {
            let before = recorder.snapshot().count
            let outcome = try await directory.authenticateForLogin(
                handle: handle,
                password: "definitely wrong"
            )
            XCTAssertEqual(outcome, .rejected, handle)
            let calls = recorder.snapshot()
            XCTAssertEqual(calls.count, before + 1, handle)
            XCTAssertEqual(calls.last, expectedVerifier, handle)
        }
    }

    func testLoginAuthenticationSurfacesVerifierSaturationInsteadOfBadCredentials() async throws {
        let release = DispatchSemaphore(value: 0)
        let executor = try Argon2idVerificationExecutor(
            maximumConcurrentVerifications: 1,
            maximumQueuedVerifications: 0
        ) { _, _ in
            release.wait()
            return false
        }
        let directory = DurableAccountDirectory(
            store: LoginShapeAccountStore(),
            passwordHasher: LoginDummyHasher(),
            verificationExecutor: executor
        )
        let admitted = Task {
            try await directory.authenticateForLogin(
                handle: "unknown.example.com",
                password: "first"
            )
        }
        defer { release.signal() }
        try await waitForLoginCondition {
            await executor.metrics().active == 1
        }

        do {
            _ = try await directory.authenticateForLogin(
                handle: "another-unknown.example.com",
                password: "second"
            )
            XCTFail("saturated Argon2 admission was reported as a credential result")
        } catch {
            XCTAssertEqual(error as? AccountLoginAuthenticationError, .unavailable)
        }

        release.signal()
        let admittedResult = try await admitted.value
        XCTAssertEqual(admittedResult, .rejected)
    }

    func testLoginAdmissionIsDurableBoundedAndPersistsOnlyHMACKeys() async throws {
        let root = try temporaryLoginDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = try AccountLoginAdmissionKey(Data(repeating: 0xA7, count: 32))
        let policy = try AccountLoginAdmissionPolicy(
            handleAttempts: 2,
            directPeerAttempts: 2,
            pairAttempts: 2,
            window: 300,
            maximumProcessEntries: 64,
            maximumDurableEntries: 3
        )
        let first = try await SQLiteControlDatabase(dataDirectory: root)
        let firstService = AccountLoginAdmissionService(
            store: first,
            key: key,
            policy: policy
        )
        let handle = "private-person.example.com"
        let directPeer = "203.0.113.47"

        let firstAdmission = try await firstService.admit(
            handle: handle,
            directPeer: directPeer,
            now: Date(timeIntervalSince1970: 1_800_000_000)
        )
        XCTAssertEqual(firstAdmission, .allowed)
        try await first.close()

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        let restartedService = AccountLoginAdmissionService(
            store: reopened,
            key: key,
            policy: policy
        )
        let restartedAdmission = try await restartedService.admit(
            handle: handle,
            directPeer: directPeer,
            now: Date(timeIntervalSince1970: 1_800_000_001)
        )
        XCTAssertEqual(restartedAdmission, .allowed)
        let limitedAdmission = try await restartedService.admit(
            handle: handle,
            directPeer: directPeer,
            now: Date(timeIntervalSince1970: 1_800_000_002)
        )
        XCTAssertEqual(limitedAdmission, .rateLimited)

        let variedHandleAdmission = try await restartedService.admit(
            handle: "table-cap-attacker.example.com",
            directPeer: directPeer,
            now: Date(timeIntervalSince1970: 1_800_000_003)
        )
        XCTAssertEqual(
            variedHandleAdmission,
            .rateLimited,
            "a limited peer must not allocate varied-handle or pair rows"
        )
        do {
            _ = try await restartedService.admit(
                handle: "table-cap-attacker.example.com",
                directPeer: "203.0.113.99",
                now: Date(timeIntervalSince1970: 1_800_000_004)
            )
            XCTFail("a full durable admission table failed open")
        } catch {
            XCTAssertEqual(error as? AccountLoginAdmissionError, .unavailable)
        }

        let afterExpiry = AccountLoginAdmissionService(
            store: reopened,
            key: key,
            policy: policy
        )
        let afterExpiryAdmission = try await afterExpiry.admit(
            handle: "after-expiry.example.com",
            directPeer: "203.0.113.99",
            now: Date(timeIntervalSince1970: 1_800_000_301)
        )
        XCTAssertEqual(
            afterExpiryAdmission,
            .allowed,
            "indexed expiry cleanup must reclaim a full table"
        )
        try assertLoginAdmissionFilesDoNotContain(
            [
                handle,
                directPeer,
                "table-cap-attacker.example.com",
                "after-expiry.example.com",
            ],
            in: root
        )
        try await reopened.close()
        try assertLoginAdmissionFilesDoNotContain(
            [
                handle,
                directPeer,
                "table-cap-attacker.example.com",
                "after-expiry.example.com",
            ],
            in: root
        )
    }

    func testInvalidHandleSpellingsShareOneBoundedAdmissionBucket() async throws {
        let root = try temporaryLoginDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let service = AccountLoginAdmissionService(
            store: database,
            key: try AccountLoginAdmissionKey(Data(repeating: 0xB8, count: 32)),
            policy: try AccountLoginAdmissionPolicy(
                handleAttempts: 1,
                directPeerAttempts: 100,
                pairAttempts: 1,
                window: 300,
                maximumProcessEntries: 64,
                maximumDurableEntries: 64
            )
        )
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let firstInvalidAdmission = try await service.admit(
            handle: "not a handle",
            directPeer: "203.0.113.70",
            now: now
        )
        XCTAssertEqual(firstInvalidAdmission, .allowed)
        let secondInvalidAdmission = try await service.admit(
            handle: "a different invalid handle",
            directPeer: "203.0.113.70",
            now: now.addingTimeInterval(1)
        )
        XCTAssertEqual(
            secondInvalidAdmission,
            .rateLimited,
            "invalid spellings must not create attacker-controlled bucket cardinality"
        )
        try await database.close()
    }

    func testLegacyWindowDurationAdmissionSchemaMigratesWithoutResettingAttempts() async throws {
        let root = try temporaryLoginDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let initial = try await SQLiteControlDatabase(dataDirectory: root)
        try await initial.close()

        let legacy = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.controlDatabase(in: root).path)
        )
        _ = try await legacy.query(
            "DROP TRIGGER IF EXISTS account_login_rate_limit_count_insert"
        )
        _ = try await legacy.query(
            "DROP TRIGGER IF EXISTS account_login_rate_limit_count_delete"
        )
        _ = try await legacy.query(
            "DROP INDEX IF EXISTS account_login_rate_limits_expiry"
        )
        _ = try await legacy.query(
            "DROP TABLE account_login_rate_limits"
        )
        _ = try await legacy.query(
            "DROP TABLE account_login_rate_limit_capacity"
        )
        _ = try await legacy.query(
            """
            CREATE TABLE account_login_rate_limits (
                scope TEXT NOT NULL,
                key_digest BLOB NOT NULL,
                window_started_at INTEGER NOT NULL,
                window_microseconds INTEGER NOT NULL,
                attempts INTEGER NOT NULL,
                PRIMARY KEY(scope, key_digest)
            ) WITHOUT ROWID
            """
        )
        let buckets = try AccountLoginRateLimitScope.allCases.enumerated().map {
            offset, scope in
            try AccountLoginRateLimitBucket(
                scope: scope,
                keyDigest: Data(repeating: UInt8(0xC1 + offset), count: 32),
                maximumAttempts: 2,
                window: 300
            )
        }
        for bucket in buckets {
            _ = try await legacy.query(
                """
                INSERT INTO account_login_rate_limits(
                    scope, key_digest, window_started_at,
                    window_microseconds, attempts
                ) VALUES (?, ?, 1000000, 300000000, 1)
                """,
                [
                    .text(bucket.scope.rawValue),
                    bucket.keyDigest.sqliteData!,
                ]
            )
        }
        try await legacy.close()

        let migrated = try await SQLiteControlDatabase(dataDirectory: root)
        let request = try AccountLoginRateLimitRequest(
            buckets: buckets,
            maximumEntries: 64
        )
        let migratedAdmission = try await migrated.consumeLoginRateLimit(
            request,
            now: Date(timeIntervalSince1970: 2)
        )
        XCTAssertEqual(migratedAdmission, .allowed)
        let migratedLimitedAdmission =
            try await migrated.consumeLoginRateLimit(
                request,
                now: Date(timeIntervalSince1970: 3)
            )
        XCTAssertEqual(
            migratedLimitedAdmission,
            .limited,
            "migration must preserve the legacy attempt count"
        )
        try await migrated.close()
    }

    func testRequestedExpiredBucketsAreReclaimedBehindBoundedGlobalCleanup() async throws {
        let root = try temporaryLoginDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let initial = try await SQLiteControlDatabase(dataDirectory: root)
        try await initial.close()

        let raw = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.controlDatabase(in: root).path)
        )
        _ = try await raw.query(
            """
            WITH RECURSIVE sequence(value) AS (
                SELECT 1
                UNION ALL
                SELECT value + 1 FROM sequence WHERE value < 513
            )
            INSERT INTO account_login_rate_limits(
                scope, key_digest, window_started_at, expires_at, attempts
            )
            SELECT 'direct-peer', randomblob(32), 0, 8000000, 1
            FROM sequence
            """
        )
        let requested = try AccountLoginRateLimitScope.allCases.enumerated().map {
            offset, scope in
            try AccountLoginRateLimitBucket(
                scope: scope,
                keyDigest: Data(repeating: UInt8(0xE1 + offset), count: 32),
                maximumAttempts: 2,
                window: 300
            )
        }
        for bucket in requested {
            _ = try await raw.query(
                """
                INSERT INTO account_login_rate_limits(
                    scope, key_digest, window_started_at, expires_at, attempts
                ) VALUES (?, ?, 0, 9000000, 1)
                """,
                [
                    .text(bucket.scope.rawValue),
                    bucket.keyDigest.sqliteData!,
                ]
            )
        }
        try await raw.close()

        let database = try await SQLiteControlDatabase(dataDirectory: root)
        let reclaimedAdmission =
            try await database.consumeLoginRateLimit(
                try AccountLoginRateLimitRequest(
                    buckets: requested,
                    maximumEntries: 1_000
                ),
                now: Date(timeIntervalSince1970: 10)
            )
        XCTAssertEqual(
            reclaimedAdmission,
            .allowed,
            "the three requested expired rows must be point-reclaimed before capped cleanup"
        )
        try await database.close()
    }
}

private struct LoginDummyHasher: PasswordHasher {
    func hash(_: String) throws -> String {
        AccountLoginHardeningTests.dummyVerifier
    }

    func verify(_: String, encodedHash _: String) throws -> Bool {
        false
    }

    func needsRehash(_ encodedHash: String) throws -> Bool {
        encodedHash == AccountLoginHardeningTests.parameterVariantVerifier
    }
}

private final class LoginVerificationRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var verifiers: [String] = []

    func record(_ verifier: String) {
        lock.lock()
        verifiers.append(verifier)
        lock.unlock()
    }

    func snapshot() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return verifiers
    }
}

private actor LoginShapeAccountStore: AccountControlStore {
    func createAccount(_: AccountControlRegistration) async throws -> AccountControlAccount {
        throw AccountControlStoreError.unavailable
    }

    func account(did _: String) async throws -> AccountControlAccount? {
        nil
    }

    func account(canonicalHandle: String) async throws -> AccountControlAccount? {
        switch canonicalHandle {
        case "known-wrong.example.com":
            try account(
                did: AccountLoginHardeningTests.knownDID,
                handle: canonicalHandle,
                status: .active,
                credentialState: .configured
            )
        case "inactive.example.com":
            try account(
                did: AccountLoginHardeningTests.knownDID,
                handle: canonicalHandle,
                status: .deactivated,
                credentialState: .configured
            )
        case "missing.example.com":
            try account(
                did: AccountLoginHardeningTests.missingDID,
                handle: canonicalHandle,
                status: .active,
                credentialState: .missing
            )
        case "malformed-verifier.example.com":
            try account(
                did: AccountLoginHardeningTests.malformedDID,
                handle: canonicalHandle,
                status: .active,
                credentialState: .configured
            )
        case "parameter-variant.example.com":
            try account(
                did: "did:plc:cdefghijklmnopqrstuvwxyz",
                handle: canonicalHandle,
                status: .active,
                credentialState: .configured
            )
        default:
            nil
        }
    }

    func credential(did: String) async throws -> AccountControlCredential? {
        switch did {
        case AccountLoginHardeningTests.knownDID:
            return try AccountControlCredential(
                did: did,
                verifier: AccountLoginHardeningTests.realVerifier,
                updatedAt: Date(timeIntervalSince1970: 1_700_000_000)
            )
        case AccountLoginHardeningTests.missingDID:
            return nil
        case AccountLoginHardeningTests.malformedDID:
            throw AccountControlStoreError.malformedRecord
        case "did:plc:cdefghijklmnopqrstuvwxyz":
            return try AccountControlCredential(
                did: did,
                verifier: AccountLoginHardeningTests.parameterVariantVerifier,
                updatedAt: Date(timeIntervalSince1970: 1_700_000_000)
            )
        default:
            return nil
        }
    }

    func replaceCredential(
        did _: String,
        expectedVerifier _: String,
        replacementVerifier _: String,
        now _: Date
    ) async throws -> AccountCredentialReplacement {
        .unchanged
    }

    func finalizeAuthentication(
        did _: String,
        expectedVerifier _: String,
        replacementVerifier _: String?,
        now _: Date
    ) async throws -> AccountAuthenticationFinalization? {
        nil
    }

    func transitionStatus(
        did _: String,
        to _: AccountControlStatus,
        declaration _: AccountLifecycleDeclaration,
        emitting _: AccountLifecycleEmission?,
        now _: Date
    ) async throws -> AccountControlAccount {
        throw AccountControlStoreError.unavailable
    }

    private func account(
        did: String,
        handle: String,
        status: AccountControlStatus,
        credentialState: AccountCredentialState
    ) throws -> AccountControlAccount {
        try AccountControlAccount(
            did: did,
            canonicalHandle: handle,
            status: status,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            credentialState: credentialState,
            signingKey: nil,
            rotationKey: nil
        )
    }
}

private func temporaryLoginDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appending(path: "AccountLoginHardeningTests-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
        at: url,
        withIntermediateDirectories: true
    )
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: url.path
    )
    return url
}

private func assertLoginAdmissionFilesDoNotContain(
    _ rawValues: [String],
    in root: URL,
    file: StaticString = #filePath,
    line: UInt = #line
) throws {
    let database = SQLiteLayout.controlDatabase(in: root)
    for url in [
        database,
        URL(fileURLWithPath: database.path + "-wal"),
        URL(fileURLWithPath: database.path + "-shm"),
    ] where FileManager.default.fileExists(atPath: url.path) {
        let bytes = try Data(contentsOf: url)
        for rawValue in rawValues {
            XCTAssertNil(
                bytes.range(of: Data(rawValue.utf8)),
                "raw login admission value leaked into \(url.lastPathComponent)",
                file: file,
                line: line
            )
        }
    }
}

private func waitForLoginCondition(
    timeout: Duration = .seconds(2),
    _ condition: @escaping @Sendable () async -> Bool
) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: timeout)
    while clock.now < deadline {
        if await condition() {
            return
        }
        try await Task.sleep(for: .milliseconds(10))
    }
    XCTFail("timed out waiting for login condition")
}
