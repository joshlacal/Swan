import Foundation
import SwanCore
import SwanSQLite
import SwanSpaces
import XCTest
@testable import SwanOAuth

/// atproto#5567 repo-host revocation storage: keyed by `(space, jti)`,
/// idempotent, retained for at least 3610 s from receipt, and never removed
/// by cleanup before its deadline.
final class SpaceCredentialRevocationStoreTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_750_000_000)

    func testRetentionCoversTheCeilingAndBothClockAllowances() {
        XCTAssertEqual(DurableSpaceCredentialRevocations.retention, 3_905)
        XCTAssertGreaterThanOrEqual(DurableSpaceCredentialRevocations.retention, 3_600 + 2 * 5)
        XCTAssertGreaterThanOrEqual(
            DurableSpaceCredentialRevocations.retention,
            PermissionedDataJWT.spaceCredentialLifetime
                + TimeInterval(PermissionedDataJWT.spaceCredentialMaximumIssuedAtLead)
                + DurableSpaceCredentialVerifier.Configuration.maximumClockSkew
        )
    }

    func testRevocationIsKeyedBySpaceAndJTIAndIsIdempotent() async throws {
        let fixture = try await Fixture()
        defer { fixture.cleanup() }
        let revocations = DurableSpaceCredentialRevocations(store: fixture.database)
        let space = try SpaceURI(authority: "did:plc:abcdefghijklmnopqrstuvwx", spaceType: "app.bsky.bookmarks", skey: "a")
        let other = try SpaceURI(authority: "did:plc:abcdefghijklmnopqrstuvwx", spaceType: "app.bsky.bookmarks", skey: "b")

        let isRevokedBeforeRecord = try await revocations.isRevoked(space: space, credentialID: "jti-1", now: t0)
        XCTAssertFalse(isRevokedBeforeRecord, "positive control: nothing recorded yet")
        try await revocations.record(space: space, credentialIDs: ["jti-1", "jti-2", "jti-1"], now: t0)
        try await revocations.record(space: space, credentialIDs: ["jti-1"], now: t0)
        let revoked1 = try await revocations.isRevoked(space: space, credentialID: "jti-1", now: t0)
        let revoked2 = try await revocations.isRevoked(space: space, credentialID: "jti-2", now: t0)
        let otherJTI = try await revocations.isRevoked(space: space, credentialID: "jti-3", now: t0)
        let otherSpace = try await revocations.isRevoked(space: other, credentialID: "jti-1", now: t0)
        XCTAssertTrue(revoked1)
        XCTAssertTrue(revoked2)
        XCTAssertFalse(otherJTI)
        XCTAssertFalse(otherSpace)
        try await fixture.database.close()
    }

    func testRetentionLastsAtLeastTheWindowAndRepeatsOnlyExtendIt() async throws {
        let fixture = try await Fixture()
        defer { fixture.cleanup() }
        let revocations = DurableSpaceCredentialRevocations(store: fixture.database)
        let space = try SpaceURI(authority: "did:plc:abcdefghijklmnopqrstuvwx", spaceType: "app.bsky.bookmarks", skey: "window")
        let retention = DurableSpaceCredentialRevocations.retention

        try await revocations.record(space: space, credentialIDs: ["jti"], now: t0)
        let atReferenceWindow = try await revocations.isRevoked(space: space, credentialID: "jti", now: t0.addingTimeInterval(3_610))
        let justBeforeDeadline = try await revocations.isRevoked(space: space, credentialID: "jti", now: t0.addingTimeInterval(retention - 1))
        let atDeadline = try await revocations.isRevoked(space: space, credentialID: "jti", now: t0.addingTimeInterval(retention))
        XCTAssertTrue(atReferenceWindow)
        XCTAssertTrue(justBeforeDeadline)
        XCTAssertFalse(atDeadline)

        // A repeat later extends; an earlier deadline never shortens it.
        try await revocations.record(space: space, credentialIDs: ["jti"], now: t0.addingTimeInterval(100))
        try await fixture.database.recordSpaceCredentialRevocations(
            digests: [DurableSpaceCredentialRevocations.digest(space: space, credentialID: "jti")],
            retainUntil: t0.addingTimeInterval(200),
            now: t0.addingTimeInterval(150)
        )
        let extended = try await revocations.isRevoked(space: space, credentialID: "jti", now: t0.addingTimeInterval(retention + 50))
        XCTAssertTrue(extended)
        try await fixture.database.close()
    }

    func testCleanupNeverRemovesALiveRevocationAndStatePersistsAcrossReopen() async throws {
        let fixture = try await Fixture()
        defer { fixture.cleanup() }
        let space = try SpaceURI(authority: "did:plc:abcdefghijklmnopqrstuvwx", spaceType: "app.bsky.bookmarks", skey: "purge")
        do {
            let revocations = DurableSpaceCredentialRevocations(store: fixture.database)
            try await revocations.record(space: space, credentialIDs: ["early"], now: t0)
            // A later write purges expired rows inside the same transaction;
            // `early` is still within its window and must survive it.
            try await revocations.record(space: space, credentialIDs: ["later"], now: t0.addingTimeInterval(3_000))
            let earlyLive = try await revocations.isRevoked(space: space, credentialID: "early", now: t0.addingTimeInterval(3_000))
            XCTAssertTrue(earlyLive)
            // After its deadline, a purging write may drop it; `later` stays.
            try await revocations.record(space: space, credentialIDs: ["latest"], now: t0.addingTimeInterval(4_000))
            let earlyGone = try await revocations.isRevoked(space: space, credentialID: "early", now: t0.addingTimeInterval(4_000))
            let laterLive = try await revocations.isRevoked(space: space, credentialID: "later", now: t0.addingTimeInterval(4_000))
            XCTAssertFalse(earlyGone)
            XCTAssertTrue(laterLive)
            try await fixture.database.close()
        }
        let reopened = try await SQLiteControlDatabase(dataDirectory: fixture.root)
        do {
            let revocations = DurableSpaceCredentialRevocations(store: reopened)
            let persisted = try await revocations.isRevoked(space: space, credentialID: "later", now: t0.addingTimeInterval(4_000))
            XCTAssertTrue(persisted)
            try await reopened.close()
        } catch {
            try? await reopened.close()
            throw error
        }
    }

    func testInvalidRevocationListsAreRejected() async throws {
        let fixture = try await Fixture()
        defer { fixture.cleanup() }
        let revocations = DurableSpaceCredentialRevocations(store: fixture.database)
        let space = try SpaceURI(authority: "did:plc:abcdefghijklmnopqrstuvwx", spaceType: "app.bsky.bookmarks", skey: "invalid")
        for credentialIDs in [
            [],
            Array(repeating: "jti", count: 101),
            [""],
            ["bad\u{0}jti"],
            [String(repeating: "j", count: PermissionedDataJWT.maximumOpaqueJTIBytes + 1)],
        ] {
            do {
                try await revocations.record(space: space, credentialIDs: credentialIDs, now: t0)
                XCTFail("accepted \(credentialIDs.count) invalid credential IDs")
            } catch {
                XCTAssertEqual(error as? SwanError, .malformed("credential revocation list is invalid"))
            }
        }
        // The 100-ID bound itself is accepted.
        try await revocations.record(
            space: space,
            credentialIDs: (0 ..< 100).map { "jti-\($0)" },
            now: t0
        )
        try await fixture.database.close()
    }
}

private struct Fixture {
    let root: URL
    let database: SQLiteControlDatabase

    init() async throws {
        root = FileManager.default.temporaryDirectory
            .appending(path: "SpaceCredentialRevocationStoreTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
        )
        database = try await SQLiteControlDatabase(dataDirectory: root)
    }

    func cleanup() { try? FileManager.default.removeItem(at: root) }
}
