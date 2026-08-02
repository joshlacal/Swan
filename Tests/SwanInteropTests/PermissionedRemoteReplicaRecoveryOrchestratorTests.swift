import Crypto
import Foundation
import Petrel
import XCTest
@testable import SwanInterop
import SwanOAuth
import SwanSQLite
import SwanSpaces
import SwanStorage

final class PermissionedRemoteReplicaRecoveryOrchestratorTests: XCTestCase {
    private let receiver = "did:plc:receiverabcdefghijklmnopqrstu"
    private let repository = "did:plc:writerabcdefghijklmnopqrstuv"

    func testAuthenticatedSourceSessionStagesAndPublishesVerifiedRecovery() async throws {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "SwanRemoteRecoveryOrchestrator-" + UUID().uuidString
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: receiver
        )
        defer { Task { try? await database.close() } }

        let fixture = try makeCAR()
        let key = fixture.key
        let verificationKey = PermissionedDataJWTVerificationKey.p256(
            key.publicKey
        )
        let sourceIdentity = try PermissionedRemoteReplicaSourceIdentity(
            origin: URL(string: "https://writer.example")!,
            repositoryDID: repository,
            verifierIdentity: verificationKey.recoveryVerifierIdentity
        )
        let source = try PermissionedRemoteReplicaSourceSession(
            identity: sourceIdentity,
            verificationKey: verificationKey,
            freshnessWitness: .init(
                wireRevision: fixture.revision,
                commitment: fixture.commitment
            ),
            source: TestRecoveryByteSource(bytes: fixture.car),
            closeSource: {}
        )
        let target = try makeTarget()
        let clock = TestRecoveryClock(value: 1_750_000_000)
        let publicationCounter = RecoveryCloseCounter()
        let orchestrator = PermissionedRemoteReplicaRecoveryOrchestrator(
            database: database,
            now: { clock.value },
            publicationAuthorization: { operation in
                await publicationCounter.increment()
                return try await operation()
            }
        )

        let result = try await orchestrator.recover(
            target: target,
            requestID: "recovery-1",
            source: source,
            profileID: "permissioned-data-0016-test",
            expiresAt: 1_750_000_600,
            limits: try SpaceCARRecoveryLimits(
                maximumCARBytes: fixture.car.count
            )
        )

        XCTAssertEqual(result.head.target, target)
        XCTAssertEqual(result.head.wireRevision, fixture.revision)
        XCTAssertEqual(result.head.commitment, fixture.commitment)
        XCTAssertEqual(result.recordCount, 1)
        XCTAssertEqual(
            result.verifierIdentity,
            verificationKey.recoveryVerifierIdentity
        )
        let publicationCount = await publicationCounter.value
        XCTAssertEqual(publicationCount, 1)
        let head = try await database.permissionedRemoteReplicaHead(target: target)
        XCTAssertEqual(head, result.head)
    }

    func testSourceIdentityAndKeyMismatchFailsBeforeDurableSessionCreation() throws {
        let key = P256.Signing.PrivateKey()
        let wrongKey = P256.Signing.PrivateKey()
        let identity = try PermissionedRemoteReplicaSourceIdentity(
            origin: URL(string: "https://writer.example/")!,
            repositoryDID: repository,
            verifierIdentity: PermissionedDataJWTVerificationKey.p256(
                key.publicKey
            ).recoveryVerifierIdentity
        )

        XCTAssertThrowsError(
            try PermissionedRemoteReplicaSourceSession(
                identity: identity,
                verificationKey: .p256(wrongKey.publicKey),
                freshnessWitness: .init(
                    wireRevision: try TID(tidString: "222222222222a"),
                    commitment: Data(repeating: 0x01, count: 32)
                ),
                source: TestRecoveryByteSource(bytes: Data()),
                closeSource: {}
            )
        ) { error in
            XCTAssertEqual(
                error as? PermissionedRemoteReplicaRecoveryError,
                .invalidBinding
            )
        }
    }

    func testSourceSessionClosesWhenPreflightRejectsBeforeStaging() async throws {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "SwanRemoteRecoveryClose-" + UUID().uuidString
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: receiver
        )
        defer { Task { try? await database.close() } }

        let key = P256.Signing.PrivateKey()
        let verificationKey = PermissionedDataJWTVerificationKey.p256(
            key.publicKey
        )
        let identity = try PermissionedRemoteReplicaSourceIdentity(
            origin: URL(string: "https://writer.example")!,
            repositoryDID: repository,
            verifierIdentity: verificationKey.recoveryVerifierIdentity
        )
        let closeCounter = RecoveryCloseCounter()
        let source = try PermissionedRemoteReplicaSourceSession(
            identity: identity,
            verificationKey: verificationKey,
            freshnessWitness: .init(
                wireRevision: try TID(tidString: "222222222222a"),
                commitment: Data(repeating: 0x01, count: 32)
            ),
            source: TestRecoveryByteSource(bytes: Data()),
            closeSource: {
                await closeCounter.increment()
            }
        )
        let orchestrator = PermissionedRemoteReplicaRecoveryOrchestrator(
            database: database,
            now: { 100 }
        )

        do {
            _ = try await orchestrator.recover(
                target: try makeTarget(),
                requestID: "expired-recovery",
                source: source,
                profileID: "permissioned-data-0016-test",
                expiresAt: 100
            )
            XCTFail("expired source session should be rejected")
        } catch {
            XCTAssertEqual(
                error as? PermissionedRemoteReplicaRecoveryError,
                .expiredSession
            )
        }
        let closeCount = await closeCounter.value
        XCTAssertEqual(closeCount, 1)
    }

    func testSourceSessionCloseIsExactlyOnceWhenVerificationFails() async throws {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "SwanRemoteRecoveryCloseOnVerify-" + UUID().uuidString
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteAccountDatabase(
            dataDirectory: root,
            did: receiver
        )
        defer { Task { try? await database.close() } }

        let fixture = try makeCAR()
        let verificationKey = PermissionedDataJWTVerificationKey.p256(
            fixture.key.publicKey
        )
        let identity = try PermissionedRemoteReplicaSourceIdentity(
            origin: URL(string: "https://writer.example")!,
            repositoryDID: repository,
            verifierIdentity: verificationKey.recoveryVerifierIdentity
        )
        let closeCounter = RecoveryCloseCounter()
        let source = try PermissionedRemoteReplicaSourceSession(
            identity: identity,
            verificationKey: verificationKey,
            freshnessWitness: .init(
                wireRevision: fixture.revision,
                commitment: fixture.commitment
            ),
            source: TestRecoveryByteSource(bytes: Data([0x00])),
            closeSource: {
                await closeCounter.increment()
            }
        )
        let target = try makeTarget()
        let orchestrator = PermissionedRemoteReplicaRecoveryOrchestrator(
            database: database,
            now: { 1_750_000_000 }
        )

        do {
            _ = try await orchestrator.recover(
                target: target,
                requestID: "verification-failure",
                source: source,
                profileID: "permissioned-data-0016-test",
                expiresAt: 1_750_000_600,
                limits: .standard
            )
            XCTFail("malformed CAR should be rejected")
        } catch {
            // The exact parser error is intentionally not part of this
            // ownership regression; all terminal paths must still close once.
        }

        let closeCount = await closeCounter.value
        XCTAssertEqual(closeCount, 1)
        let head = try await database.permissionedRemoteReplicaHead(
            target: target
        )
        XCTAssertNil(head)
    }

    func testInvalidOriginAndRepositoryMismatchAreRejected() throws {
        XCTAssertNil(
            PermissionedRemoteReplicaSourceIdentity.canonicalOrigin(
                URL(string: "http://writer.example")!
            )
        )
        XCTAssertEqual(
            PermissionedRemoteReplicaSourceIdentity.canonicalOrigin(
                URL(string: "https://writer.example/")!
            ),
            "https://writer.example"
        )
        XCTAssertThrowsError(
            try PermissionedRemoteReplicaSourceIdentity(
                origin: URL(string: "http://writer.example")!,
                repositoryDID: repository,
                verifierIdentity: "key-sha256:" + String(repeating: "a", count: 64)
            )
        )
        XCTAssertThrowsError(
            try PermissionedRemoteReplicaSourceIdentity(
                origin: URL(string: "https://writer.example/path")!,
                repositoryDID: repository,
                verifierIdentity: "key-sha256:" + String(repeating: "a", count: 64)
            )
        )
        let loopback = try PermissionedRemoteReplicaSourceIdentity(
            origin: URL(string: "http://[::1]:3000/")!,
            repositoryDID: repository,
            verifierIdentity: "key-sha256:" + String(repeating: "a", count: 64)
        )
        XCTAssertEqual(loopback.origin, "http://[::1]:3000")
        let key = P256.Signing.PrivateKey()
        let source = try PermissionedRemoteReplicaSourceIdentity(
            origin: URL(string: "https://writer.example")!,
            repositoryDID: repository,
            verifierIdentity: PermissionedDataJWTVerificationKey.p256(
                key.publicKey
            ).recoveryVerifierIdentity
        )
        let target = try makeTarget()
        XCTAssertThrowsError(
            try PermissionedRemoteReplicaImportBinding(
                requestID: "mismatch",
                requestDigest: Data(repeating: 0x01, count: 32),
                source: source,
                target: try PermissionedRemoteReplicaTarget(
                    receiverDID: receiver,
                    space: target.space,
                    repositoryDID: "did:plc:otherabcdefghijklmnopqrstu"
                ),
                expectedBase: nil,
                freshnessWitness: .init(
                    wireRevision: try TID(tidString: "222222222222a"),
                    commitment: Data(repeating: 0x01, count: 32)
                ),
                profileID: "permissioned-data-0016-test"
            )
        ) { error in
            XCTAssertEqual(
                error as? PermissionedRemoteReplicaRecoveryError,
                .invalidBinding
            )
        }
    }

    private func makeTarget() throws -> PermissionedRemoteReplicaTarget {
        try PermissionedRemoteReplicaTarget(
            receiverDID: receiver,
            space: SpaceURI(
                authority: "did:plc:authorityabcdefghijklmnopqrs",
                spaceType: "app.swan.test",
                skey: "recovery"
            ),
            repositoryDID: repository
        )
    }

    private func makeCAR() throws -> RecoveryCARFixture {
        let target = try makeTarget()
        let value = Data([0xa1, 0x61, 0x78, 0x01])
        let uri = try SpaceRecordURI(
            space: target.space,
            author: repository,
            collection: "app.bsky.feed.post",
            rkey: "one"
        )
        let cid = CID.fromDAGCBOR(value)
        let record = SpaceRecord(
            uri: uri,
            value: value,
            cid: cid.string,
            revision: 1
        )
        var hash = LtHash()
        hash.add(element: "app.bsky.feed.post/one/\(cid.string)")
        let key = P256.Signing.PrivateKey()
        let revision = try TID(tidString: "222222222222a")
        let commit = try SpaceCommitCodec.sign(
            context: try SpaceCommitContext(
                space: target.space,
                author: repository,
                rev: revision.toString(),
                ikm: Data(repeating: 0x42, count: 32)
            ),
            commitment: hash.commitment,
            key: key
        )
        let car = try SpaceCARCodec.encode(commit: commit, records: [record])
        return RecoveryCARFixture(
            car: car.data,
            key: key,
            revision: revision,
            commitment: hash.commitment
        )
    }
}

private struct RecoveryCARFixture: Sendable {
    let car: Data
    let key: P256.Signing.PrivateKey
    let revision: TID
    let commitment: Data
}

private actor TestRecoveryByteSource: SpaceCARRecoveryByteSource {
    private let bytes: Data
    private var offset = 0

    init(bytes: Data) { self.bytes = bytes }

    func read(maximumBytes: Int) async throws -> Data? {
        guard maximumBytes > 0 else { return nil }
        guard offset < bytes.count else { return nil }
        let end = min(bytes.count, offset + maximumBytes)
        let chunk = bytes[offset ..< end]
        offset = end
        return Data(chunk)
    }
}

private actor RecoveryCloseCounter {
    private(set) var value = 0

    func increment() {
        value += 1
    }
}

private final class TestRecoveryClock: @unchecked Sendable {
    let value: Int64
    init(value: Int64) { self.value = value }
}
