import Crypto
import Foundation
@testable import SwanSQLite
import SwanStorage
import XCTest

final class AccountPortalSessionStoreTests: XCTestCase {
    func testPreAuthConsumeAndSessionIssueAreOneTransaction() async throws {
        let root = try portalTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }
        try await database.migrateAccountPortalSessionSchema()
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        _ = try await database.createAccount(try portalRegistration(did: did, handle: "portal.example.com", now: now))
        let preAuth = Data(repeating: 0x01, count: 32)
        let sessionDigest = Data(repeating: 0x02, count: 32)
        let csrfDigest = Data(repeating: 0x03, count: 32)
        await database.put(digest: preAuth, expiresAt: now.addingTimeInterval(60))
        let metadata = try ManagementSessionMetadata(
            sessionID: try ManagementSessionID(rawValue: String(repeating: "a", count: 43)),
            accountDID: did,
            issuedAt: now,
            idleExpiresAt: now.addingTimeInterval(60),
            absoluteExpiresAt: now.addingTimeInterval(600),
            strength: .password
        )

        let created = try await database.consumePreAuthAndCreateManagementSession(
            preAuthDigest: preAuth,
            session: metadata,
            sessionDigest: sessionDigest,
            csrfDigest: csrfDigest,
            now: now
        )
        XCTAssertTrue(created)
        let replay = try await database.take(digest: preAuth, now: now)
        XCTAssertFalse(replay)
        let storedCSRF = try await database.digest(for: sessionDigest)
        XCTAssertEqual(storedCSRF, csrfDigest)
        let storedSession = try await database.managementSession(digest: sessionDigest, now: now)
        XCTAssertNotNil(storedSession)
    }

    func testFailedAtomicSessionInsertDoesNotConsumePreAuth() async throws {
        let root = try portalTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }
        try await database.migrateAccountPortalSessionSchema()
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        _ = try await database.createAccount(try portalRegistration(did: did, handle: "portal-race.example.com", now: now))
        let preAuth = Data(repeating: 0x04, count: 32)
        let sessionDigest = Data(repeating: 0x05, count: 32)
        let csrfDigest = Data(repeating: 0x06, count: 32)
        await database.put(digest: preAuth, expiresAt: now.addingTimeInterval(60))
        let metadata = try ManagementSessionMetadata(
            sessionID: try ManagementSessionID(rawValue: String(repeating: "b", count: 43)),
            accountDID: did,
            issuedAt: now,
            idleExpiresAt: now.addingTimeInterval(60),
            absoluteExpiresAt: now.addingTimeInterval(600),
            strength: .password
        )
        _ = try await database.createManagementSession(metadata, sessionDigest: sessionDigest, csrfDigest: csrfDigest, now: now)
        await database.put(digest: preAuth, expiresAt: now.addingTimeInterval(60))

        do {
            _ = try await database.consumePreAuthAndCreateManagementSession(
                preAuthDigest: preAuth,
                session: metadata,
                sessionDigest: sessionDigest,
                csrfDigest: csrfDigest,
                now: now
            )
            XCTFail("duplicate session insertion must fail")
        } catch {}
        let retained = try await database.take(digest: preAuth, now: now)
        XCTAssertTrue(retained)
    }

    func testDeactivationAndReactivationRevokesManagementSessions() async throws {
        let root = try portalTestRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }
        try await database.migrateAccountPortalSessionSchema()
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        _ = try await database.createAccount(try portalRegistration(did: did, handle: "portal.example.com", now: now))

        let sessionDigest = Data(repeating: 0x04, count: 32)
        let csrfDigest = Data(repeating: 0x05, count: 32)
        let metadata = try ManagementSessionMetadata(
            sessionID: try ManagementSessionID(digest: sessionDigest),
            accountDID: did,
            issuedAt: now,
            idleExpiresAt: now.addingTimeInterval(3600),
            absoluteExpiresAt: now.addingTimeInterval(86400),
            strength: .password
        )
        try await database.createManagementSession(
            metadata,
            sessionDigest: sessionDigest,
            csrfDigest: csrfDigest,
            now: now
        )
        let activeBefore = try await database.managementSessions(accountDID: did, now: now)
        XCTAssertEqual(activeBefore.count, 1)

        _ = try await database.transitionStatus(did: did, to: .deactivated, declaration: .init(), emitting: nil, now: now.addingTimeInterval(10))
        _ = try await database.transitionStatus(did: did, to: .active, declaration: .init(), emitting: nil, now: now.addingTimeInterval(20))

        let sessionAfter = try await database.managementSession(digest: sessionDigest, now: now.addingTimeInterval(25))
        XCTAssertNotNil(sessionAfter?.revokedAt, "management session should remain revoked after deactivation and reactivation")
        let activeAfter = try await database.managementSessions(accountDID: did, now: now.addingTimeInterval(25))
        XCTAssertTrue(activeAfter.isEmpty, "active management sessions should be empty after deactivation and reactivation")
    }

    private func portalTestRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("swan-portal-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        return root
    }

    private func portalRegistration(did: String, handle: String, now: Date) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: .init(purpose: .signing, generation: 1),
            rotationKey: .init(purpose: .rotation, generation: 1),
            createdAt: now
        )
    }
}
