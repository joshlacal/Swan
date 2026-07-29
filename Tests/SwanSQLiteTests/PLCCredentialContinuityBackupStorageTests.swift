import Foundation
import Petrel
@_spi(PortableRestore) @testable import SwanSQLite
import SwanStorage
import XCTest

final class PLCCredentialContinuityBackupStorageTests: XCTestCase {
    func testInventoryIsCanonicalBoundedAndRejectsDuplicateIssuers() throws {
        let later = try checkpoint(index: 2, marker: "later")
        let earlier = try checkpoint(index: 1, marker: "earlier")

        let inventory = try PLCCredentialKeyContinuityInventory(
            checkpoints: [later, earlier]
        )

        XCTAssertEqual(inventory.checkpoints, [earlier, later])
        XCTAssertThrowsError(
            try PLCCredentialKeyContinuityInventory(
                checkpoints: [earlier, earlier]
            )
        ) {
            XCTAssertEqual(
                $0 as? PLCCredentialKeyContinuityStoreError,
                .invalidInput
            )
        }
        XCTAssertThrowsError(
            try PLCCredentialKeyContinuityInventory(
                checkpoints: (0 ... PLCCredentialKeyContinuityInventory
                    .maximumCheckpointCount).map {
                        try checkpoint(index: $0, marker: "oversized-\($0)")
                    }
            )
        ) {
            XCTAssertEqual(
                $0 as? PLCCredentialKeyContinuityStoreError,
                .invalidInput
            )
        }
    }

    func testRestoreInstallsAccountAndContinuityAsOneControlTransaction() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let checkpoints = [
                try checkpoint(index: 2, marker: "terminal-two"),
                try checkpoint(index: 1, marker: "terminal-one"),
            ]
            let account =
                try await control
                    .restoreOperatorAccountAndPLCCredentialKeyContinuity(
                        try registration(),
                        checkpoints: checkpoints
                    )

            let expectedDID = try registration().did
            let storedInventory =
                try await control.plcCredentialKeyContinuityInventory()
            XCTAssertEqual(account.did, expectedDID)
            XCTAssertEqual(
                storedInventory.checkpoints,
                checkpoints.sorted { $0.issuer < $1.issuer }
            )
            try await control.validateOperatorRestoreOnlyAccount(
                did: account.did,
                plcCredentialKeyContinuity: checkpoints
            )
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    func testDuplicateRestoreInventoryRollsBackAccountAndAllCheckpoints() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let duplicate = try checkpoint(index: 1, marker: "duplicate")
            do {
                _ =
                    try await control
                        .restoreOperatorAccountAndPLCCredentialKeyContinuity(
                            try registration(),
                            checkpoints: [duplicate, duplicate]
                        )
                XCTFail("expected duplicate continuity inventory rejection")
            } catch {
                XCTAssertEqual(
                    error as? PLCCredentialKeyContinuityStoreError,
                    .invalidInput
                )
            }

            let expectedDID = try registration().did
            let storedAccount = try await control.account(did: expectedDID)
            let storedInventory =
                try await control.plcCredentialKeyContinuityInventory()
            XCTAssertNil(storedAccount)
            XCTAssertEqual(storedInventory.checkpoints, [])
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    func testRepeatedAccountRestoreAcceptsExactInventoryAndRejectsConflictingTerminal()
        async throws
    {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let initial = try checkpoint(index: 1, marker: "shared-terminal")
            _ =
                try await control
                    .restoreOperatorAccountAndPLCCredentialKeyContinuity(
                        try registration(
                            did: "did:plc:zyxwvutsrqponmlkjihgfedc",
                            handle: "first-continuity-backup.example.com"
                        ),
                        checkpoints: [initial]
                    )
            let secondDID = "did:plc:yxwvutsrqponmlkjihgfedcb"
            _ =
                try await control
                    .restoreOperatorAccountAndPLCCredentialKeyContinuity(
                        try registration(
                            did: secondDID,
                            handle: "second-continuity-backup.example.com"
                        ),
                        checkpoints: [initial]
                    )

            let conflicting = try PLCCredentialKeyContinuityCheckpoint(
                issuer: initial.issuer,
                terminalCID: CID.fromDAGCBOR(
                    Data("conflicting-terminal".utf8)
                ).string
            )
            let thirdDID = "did:plc:xwvutsrqponmlkjihgfedcba"
            do {
                _ =
                    try await control
                        .restoreOperatorAccountAndPLCCredentialKeyContinuity(
                            try registration(
                                did: thirdDID,
                                handle: "third-continuity-backup.example.com"
                            ),
                            checkpoints: [conflicting]
                        )
                XCTFail("expected conflicting continuity rejection")
            } catch {
                XCTAssertEqual(
                    error as? PLCCredentialKeyContinuityStoreError,
                    .continuityViolation
                )
            }

            let secondAccount = try await control.account(did: secondDID)
            let thirdAccount = try await control.account(did: thirdDID)
            let storedInventory =
                try await control.plcCredentialKeyContinuityInventory()
            XCTAssertNotNil(secondAccount)
            XCTAssertNil(thirdAccount)
            XCTAssertEqual(storedInventory.checkpoints, [initial])
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    private func checkpoint(
        index: Int,
        marker: String
    ) throws -> PLCCredentialKeyContinuityCheckpoint {
        let alphabet = Array("abcdefghijklmnopqrstuvwxyz234567")
        var value = index
        var suffix = Array(repeating: Character("a"), count: 24)
        for position in suffix.indices.reversed() {
            suffix[position] = alphabet[value & 31]
            value >>= 5
        }
        return try PLCCredentialKeyContinuityCheckpoint(
            issuer: "did:plc:\(String(suffix))",
            terminalCID: CID.fromDAGCBOR(Data(marker.utf8)).string
        )
    }

    private func registration(
        did: String = "did:plc:zyxwvutsrqponmlkjihgfedc",
        handle: String = "continuity-backup.example.com"
    ) throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: did,
            canonicalHandle: handle,
            passwordVerifier:
                "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: try .init(purpose: .signing, generation: 1),
            rotationKey: try .init(purpose: .rotation, generation: 1),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "PLCCredentialContinuityBackupStorage-\(UUID().uuidString)"
        )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }
}
