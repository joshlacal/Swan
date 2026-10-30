import Foundation
import SwanStorage
@testable import SwanSQLite
import XCTest

final class AccountKEMBackfillLeaseTests: XCTestCase, @unchecked Sendable {
    func testLeaseSurvivesRestartAndStaleClaimCannotCompleteReplacement() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("swan-kem-lease-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        var db = try await SQLiteControlDatabase(dataDirectory: root)
        let did = "did:plc:abcdefghijklmnopqrstuvwx"
        _ = try await db.createAccount(registration(did, handle: "kem.example"))
        let firstValue = try await db.claimAccountKEMBackfill(now: 100)
        let first = try XCTUnwrap(firstValue)
        XCTAssertFalse(first.requiresManualPublication)
        let leased = try await db.claimAccountKEMBackfill(now: 101)
        XCTAssertNil(leased)
        try await db.close()
        db = try await SQLiteControlDatabase(dataDirectory: root)
        let retained = try await db.claimAccountKEMBackfill(now: 219)
        XCTAssertNil(retained)
        let replacementValue = try await db.claimAccountKEMBackfill(now: 220)
        let replacement = try XCTUnwrap(replacementValue)
        XCTAssertNotEqual(first.token, replacement.token)
        try await db.finishAccountKEMBackfill(first, manual: false, now: 221)
        try await db.retryAccountKEMBackfill(replacement, now: 222)
        let cooldown = try await db.claimAccountKEMBackfill(now: 281)
        XCTAssertNil(cooldown)
        let retryValue = try await db.claimAccountKEMBackfill(now: 282)
        let retry = try XCTUnwrap(retryValue)
        try await db.finishAccountKEMBackfill(retry, manual: false, now: 283)
        let completed = try await db.claimAccountKEMBackfill(now: 1000)
        XCTAssertNil(completed)
        try await db.close()
    }

    func testDidWebUsesDurableManualPublicationOutcome() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("swan-kem-manual-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let db = try await SQLiteControlDatabase(dataDirectory: root)
        _ = try await db.createAccount(registration("did:web:kem.example", handle: "kem.example"))
        let claimValue = try await db.claimAccountKEMBackfill(now: 100)
        let claim = try XCTUnwrap(claimValue)
        XCTAssertTrue(claim.requiresManualPublication)
        try await db.finishAccountKEMBackfill(claim, manual: true, now: 101)
        let completed = try await db.claimAccountKEMBackfill(now: 1000)
        XCTAssertNil(completed)
        try await db.close()
    }

    private func registration(_ did: String, handle: String) throws -> AccountControlRegistration {
        try AccountControlRegistration(did: did, canonicalHandle: handle,
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: .init(purpose: .signing, generation: 1), rotationKey: .init(purpose: .rotation, generation: 1),
            createdAt: Date(timeIntervalSince1970: 50))
    }
}
