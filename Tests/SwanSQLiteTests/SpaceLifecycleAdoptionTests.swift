import Crypto
import Foundation
import Petrel
import PetrelCrypto
import SQLiteNIO
import SwanCore
import SwanSpaces
import SwanStorage
import XCTest
@testable import SwanSQLite

/// Exercises the durable seam after JWT verification: the authorization,
/// issued-at claim and digest must belong to that same verified credential.
final class SpaceLifecycleAdoptionTests: XCTestCase {
    func testAdoptionRequiresExactEventAndFreshAuthorityReadCredential() async throws {
        let fixture = try LifecycleAdoptionFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        do {
            _ = try await fixture.install(database, requestID: "original")
            try await fixture.delete(database, eventID: "deletion-1", at: 110)
            let valid = fixture.authorization()
            let wrongSubject = AuthorizationContext.spaceCredential(SpaceGrant(
                subject: fixture.receiver, space: fixture.space, permissions: [.read], expiresAt: fixture.date(300)
            ))
            let noRead = AuthorizationContext.spaceCredential(SpaceGrant(
                subject: fixture.space.authority, space: fixture.space, permissions: [.create], expiresAt: fixture.date(300)
            ))
            let expired = fixture.authorization(expiresAt: 120)
            let attempts: [(AuthorizationContext, String, Double, Data)] = [
                (.public, "deletion-1", 111, fixture.digest),
                (valid, "another-deletion", 111, fixture.digest),
                (valid, "deletion-1", 109, fixture.digest),
                (valid, "deletion-1", 110, fixture.digest),
                (valid, "deletion-1", 121, fixture.digest),
                (wrongSubject, "deletion-1", 111, fixture.digest),
                (noRead, "deletion-1", 111, fixture.digest),
                (expired, "deletion-1", 111, fixture.digest),
                (valid, "deletion-1", 111, Data()),
            ]
            for (authorization, event, issuedAt, digest) in attempts {
                do {
                    try await database.adoptRecreatedRemoteSpace(
                        fixture.space, expectedDeletionEventID: event, authorization: authorization,
                        credentialIssuedAt: fixture.date(issuedAt), credentialDigest: digest, now: fixture.date(120)
                    )
                    XCTFail("untrusted or stale lifecycle adoption was accepted")
                } catch let error as SwanError {
                    guard case .unauthorized = error else { throw error }
                }
                let count = try await fixture.tombstoneCount(database)
                XCTAssertEqual(count, 1, "failed adoption must preserve the closure")
            }
            try await fixture.adopt(database, eventID: "deletion-1", issuedAt: 111, at: 120)
            let count = try await fixture.tombstoneCount(database)
            XCTAssertEqual(count, 0)
            let floor = try await database.remoteReplicaGenerationFloor(space: fixture.space)
            XCTAssertEqual(floor, 1)
            do {
                try await fixture.adopt(database, eventID: "deletion-1", issuedAt: 111, at: 120)
                XCTFail("adoption without the exact extant tombstone was accepted")
            } catch let error as SwanError {
                guard case .unauthorized = error else { throw error }
            }
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }

    func testGenerationFloorAndRetiredDeletionEventsSurviveTwoRecreationsAndRestart() async throws {
        let fixture = try LifecycleAdoptionFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        let lastHead: PermissionedRemoteReplicaHead
        do {
            let original = try await fixture.install(database, requestID: "original")
            try await fixture.delete(database, eventID: "deletion-1", at: 110)
            try await fixture.adopt(database, eventID: "deletion-1", issuedAt: 111, at: 120)
            let firstRecreated = try await fixture.install(database, requestID: "first-recreation")
            XCTAssertGreaterThan(firstRecreated.generation, original.generation)
            try await fixture.delete(database, eventID: "deletion-2", at: 130)
            try await fixture.adopt(database, eventID: "deletion-2", issuedAt: 131, at: 140)
            lastHead = try await fixture.install(database, requestID: "second-recreation")
            XCTAssertGreaterThan(lastHead.generation, firstRecreated.generation)
            let floor = try await database.remoteReplicaGenerationFloor(space: fixture.space)
            XCTAssertGreaterThanOrEqual(floor, firstRecreated.generation)
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
        let reopened = try await fixture.open()
        do {
            // Both the latest and older retired notifications are harmless;
            // a single last-event field is insufficient to enforce this.
            for event in ["deletion-1", "deletion-2", "deletion-1"] {
                try await fixture.delete(reopened, eventID: event, at: 150)
                let count = try await fixture.tombstoneCount(reopened)
                XCTAssertEqual(count, 0)
                let head = try await reopened.permissionedRemoteReplicaHead(target: fixture.target)
                XCTAssertEqual(head, lastHead)
            }
            try await reopened.close()
        } catch {
            try? await reopened.close()
            throw error
        }
    }

    func testNewDeletionStillClosesAdoptedLifecycle() async throws {
        let fixture = try LifecycleAdoptionFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let database = try await fixture.open()
        do {
            _ = try await fixture.install(database, requestID: "original")
            try await fixture.delete(database, eventID: "deletion-1", at: 110)
            try await fixture.adopt(database, eventID: "deletion-1", issuedAt: 111, at: 120)
            let recreated = try await fixture.install(database, requestID: "recreated")
            try await fixture.delete(database, eventID: "deletion-2", at: 130)
            let count = try await fixture.tombstoneCount(database)
            let floor = try await database.remoteReplicaGenerationFloor(space: fixture.space)
            XCTAssertEqual(count, 1)
            XCTAssertGreaterThanOrEqual(floor, recreated.generation)
            do {
                _ = try await fixture.install(database, requestID: "unapproved-recreation")
                XCTFail("a fresh deletion allowed automatic recovery")
            } catch let error as SwanError {
                guard case .unauthorized("permissioned space is closed") = error else { throw error }
            }
            try await database.close()
        } catch {
            try? await database.close()
            throw error
        }
    }
}

private struct LifecycleAdoptionFixture {
    let root = FileManager.default.temporaryDirectory.appending(path: "SwanLifecycleAdoption-\(UUID().uuidString)")
    let receiver = "did:plc:receiverabcdefghijkl"
    let space: SpaceURI
    let target: PermissionedRemoteReplicaTarget
    let digest = Data(repeating: 0x5a, count: 32)
    init() throws {
        space = try SpaceURI("at://did:plc:authorityabcdefghijk/space/app.swan.test/lifecycle")
        target = try PermissionedRemoteReplicaTarget(receiverDID: receiver, space: space, repositoryDID: "did:plc:repositoryabcdefghij")
    }
    func date(_ seconds: Double) -> Date { Date(timeIntervalSince1970: seconds) }
    func open() async throws -> SQLiteAccountDatabase {
        try await SQLiteAccountDatabase(dataDirectory: root, did: receiver)
    }
    func authorization(expiresAt: Double = 300) -> AuthorizationContext {
        .spaceCredential(SpaceGrant(subject: space.authority, space: space, permissions: [.read], expiresAt: date(expiresAt)))
    }
    func delete(_ database: SQLiteAccountDatabase, eventID: String, at time: Double) async throws {
        try await database.receiveSpaceDeletionNotification(
            space: space, issuer: space.authority, audience: receiver, eventID: eventID,
            requestBodyDigest: SpaceNotificationRequestDigest.deletion(space: space), now: date(time)
        )
    }
    func adopt(_ database: SQLiteAccountDatabase, eventID: String, issuedAt: Double, at time: Double) async throws {
        try await database.adoptRecreatedRemoteSpace(
            space, expectedDeletionEventID: eventID, authorization: authorization(),
            credentialIssuedAt: date(issuedAt), credentialDigest: digest, now: date(time)
        )
    }
    func tombstoneCount(_ database: SQLiteAccountDatabase) async throws -> Int {
        try await database.connection.query(
            "SELECT COUNT(*) AS count FROM permissioned_space_recipient_tombstones WHERE space_uri = ?", [.text(space.rawValue)]
        ).first?.column("count")?.integer ?? 0
    }
    /// An empty, valid STAR repository is sufficient to exercise durable
    /// publication generations without bypassing any verification state.
    func install(_ database: SQLiteAccountDatabase, requestID: String) async throws -> PermissionedRemoteReplicaHead {
        let revision = try TID(tidString: "222222222222a")
        let commit = try SpaceRepositoryCommit(repo: target.repositoryDID, space: space, rev: revision.toString(), data: LtHash().commitment)
        let bytes = try SpaceSTARCodec.encode(commit: commit, records: [])
        let binding = try PermissionedRemoteReplicaImportBinding(
            requestID: requestID, requestDigest: Data(SHA256.hash(data: Data(requestID.utf8))),
            source: PermissionedRemoteReplicaSourceIdentity(origin: URL(string: "https://writer.example")!, repositoryDID: target.repositoryDID, verifierIdentity: "key-sha256:" + String(repeating: "a", count: 64)),
            target: target, expectedBase: nil,
            freshnessWitness: PermissionedRemoteReplicaFreshnessWitness(wireRevision: revision, commitment: commit.data),
            profileID: "permissioned-data-0016-2026-10-29"
        )
        let outcome = try await database.createPermissionedRemoteReplicaImportSession(binding: binding, createdAt: 100, expiresAt: 200, now: 101)
        guard case let .staged(session) = outcome else { throw SwanError.malformed("unexpected lifecycle fixture import") }
        let verification = try await SpaceSTARCodec.verifyStreaming(
            source: LifecycleSTARSource(bytes), sink: EmptyLifecycleSTARSink(), space: space, author: target.repositoryDID,
            commitVerifier: { value in
                guard value == commit else { throw SpaceSTARError.badMAC }
                return true
            }
        )
        try await database.markPermissionedRemoteReplicaSTARImportVerified(sessionID: session.id, verification: verification, now: 101)
        return try await database.publishVerifiedPermissionedRemoteReplicaRecovery(
            sessionID: session.id, consumedAt: 102, now: 101, publicationAuthorization: { try await $0() }
        ).head
    }
}

private actor LifecycleSTARSource: SpaceCARRecoveryByteSource {
    let bytes: Data
    var offset = 0
    init(_ bytes: Data) { self.bytes = bytes }
    func read(maximumBytes: Int) async throws -> Data? {
        guard offset < bytes.count else { return nil }
        let end = min(bytes.count, offset + maximumBytes)
        defer { offset = end }
        return Data(bytes[offset..<end])
    }
}

private struct EmptyLifecycleSTARSink: SpaceSTARRecoverySink {
    func stage(record: SpaceRecord) async throws { throw SwanError.malformed("empty repository expected") }
    func discard() async {}
}
