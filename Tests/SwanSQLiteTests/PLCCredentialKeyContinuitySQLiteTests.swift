import Foundation
import Petrel
@_spi(PortableRestore) @testable import SwanSQLite
import SwanStorage
import XCTest

final class PLCCredentialKeyContinuitySQLiteTests: XCTestCase {
    private let issuer = "did:plc:abcdefghijklmnopqrstuvwx"

    func testCheckpointInstallAdvanceAndRollbackAreDurable() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let genesis = operationCID("genesis")
            let rotation = operationCID("rotation")
            let initial = try PLCCredentialKeyContinuityAdvance(
                issuer: issuer,
                terminalCID: genesis,
                auditCIDs: [genesis]
            )
            let installed =
                try await control.advancePLCCredentialKeyContinuity(initial)
            XCTAssertEqual(installed, initial.checkpoint)
            let idempotent =
                try await control.advancePLCCredentialKeyContinuity(initial)
            XCTAssertEqual(
                idempotent,
                initial.checkpoint,
                "installing the same authenticated terminal must be idempotent"
            )

            let advanced = try PLCCredentialKeyContinuityAdvance(
                issuer: issuer,
                terminalCID: rotation,
                auditCIDs: [genesis, rotation]
            )
            let advancedCheckpoint =
                try await control.advancePLCCredentialKeyContinuity(advanced)
            XCTAssertEqual(advancedCheckpoint, advanced.checkpoint)
            await assertThrowsContinuityError(
                try await control.advancePLCCredentialKeyContinuity(initial),
                .continuityViolation
            )
            let retained =
                try await control.plcCredentialKeyContinuityCheckpoint(
                    for: issuer
                )
            XCTAssertEqual(retained, advanced.checkpoint)
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }

        let reopened = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let loaded =
                try await reopened.plcCredentialKeyContinuityCheckpoint(
                    for: issuer
                )
            let persisted = try XCTUnwrap(
                loaded
            )
            XCTAssertEqual(persisted.terminalCID, operationCID("rotation"))
            try await reopened.close()
        } catch {
            try? await reopened.close()
            throw error
        }
    }

    func testIndependentConnectionsSerializeCompetingForkAdvances() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let first = try await SQLiteControlDatabase(dataDirectory: root)
        let second = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let genesis = operationCID("race-genesis")
            let firstFork = operationCID("race-first")
            let secondFork = operationCID("race-second")
            _ = try await first.advancePLCCredentialKeyContinuity(
                try .init(
                    issuer: issuer,
                    terminalCID: genesis,
                    auditCIDs: [genesis]
                )
            )
            let candidates = [
                try PLCCredentialKeyContinuityAdvance(
                    issuer: issuer,
                    terminalCID: firstFork,
                    auditCIDs: [genesis, firstFork]
                ),
                try PLCCredentialKeyContinuityAdvance(
                    issuer: issuer,
                    terminalCID: secondFork,
                    auditCIDs: [genesis, secondFork]
                ),
            ]

            let outcomes = await withTaskGroup(
                of: Result<PLCCredentialKeyContinuityCheckpoint, any Error>.self
            ) { group in
                group.addTask {
                    do {
                        return .success(
                            try await first.advancePLCCredentialKeyContinuity(
                                candidates[0]
                            )
                        )
                    } catch {
                        return .failure(error)
                    }
                }
                group.addTask {
                    do {
                        return .success(
                            try await second.advancePLCCredentialKeyContinuity(
                                candidates[1]
                            )
                        )
                    } catch {
                        return .failure(error)
                    }
                }
                var values = [
                    Result<PLCCredentialKeyContinuityCheckpoint, any Error>
                ]()
                for await value in group {
                    values.append(value)
                }
                return values
            }
            let successes = outcomes.compactMap { try? $0.get() }
            let failures = outcomes.compactMap { result -> (any Error)? in
                guard case let .failure(error) = result else { return nil }
                return error
            }
            XCTAssertEqual(successes.count, 1)
            XCTAssertEqual(
                failures.first as? PLCCredentialKeyContinuityStoreError,
                .continuityViolation
            )
            let retained =
                try await first.plcCredentialKeyContinuityCheckpoint(
                    for: issuer
                )
            XCTAssertEqual(retained, successes.first)
            try await second.close()
            try await first.close()
        } catch {
            try? await second.close()
            try? await first.close()
            throw error
        }
    }

    func testCandidateRejectsUnboundedOrNoncanonicalInput() throws {
        let cid = operationCID("valid")
        let otherCID = operationCID("other")
        XCTAssertThrowsError(try PLCCredentialKeyContinuityAdvance(
            issuer: "did:web:example.com",
            terminalCID: cid,
            auditCIDs: [cid]
        ))
        XCTAssertThrowsError(try PLCCredentialKeyContinuityAdvance(
            issuer: issuer,
            terminalCID: "not-a-cid",
            auditCIDs: ["not-a-cid"]
        ))
        XCTAssertThrowsError(try PLCCredentialKeyContinuityAdvance(
            issuer: issuer,
            terminalCID: cid,
            auditCIDs: []
        ))
        XCTAssertThrowsError(try PLCCredentialKeyContinuityAdvance(
            issuer: issuer,
            terminalCID: cid,
            auditCIDs: [otherCID]
        ))
        XCTAssertThrowsError(try PLCCredentialKeyContinuityAdvance(
            issuer: issuer,
            terminalCID: cid,
            auditCIDs: [cid, cid]
        ))
        XCTAssertThrowsError(try PLCCredentialKeyContinuityAdvance(
            issuer: issuer,
            terminalCID: cid,
            auditCIDs: Array(
                repeating: cid,
                count:
                    PLCCredentialKeyContinuityAdvance.maximumAuditCIDCount + 1
            )
        ))
    }

    func testCandidateRequiresTerminalToBeFinalAuditedOperation() throws {
        let retired = operationCID("retired-terminal")
        let current = operationCID("current-terminal")

        XCTAssertThrowsError(
            try PLCCredentialKeyContinuityAdvance(
                issuer: issuer,
                terminalCID: retired,
                auditCIDs: [retired, current]
            )
        ) { error in
            XCTAssertEqual(
                error as? PLCCredentialKeyContinuityStoreError,
                .invalidInput
            )
        }
    }

    func testOperatorRestoreRejectsFabricatedContinuityTrustState() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            _ = try await control.createAccount(try registration())
            let cid = operationCID("restore-fabrication")
            _ = try await control.advancePLCCredentialKeyContinuity(
                try .init(
                    issuer: issuer,
                    terminalCID: cid,
                    auditCIDs: [cid]
                )
            )
            await assertThrowsAccountControlError(
                try await control.validateOperatorRestoreOnlyAccount(did: issuer),
                .malformedRecord
            )
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    private func operationCID(_ marker: String) -> String {
        CID.fromDAGCBOR(Data(marker.utf8)).string
    }

    private func registration() throws -> AccountControlRegistration {
        try AccountControlRegistration(
            did: issuer,
            canonicalHandle: "continuity.example.com",
            passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
            signingKey: try .init(purpose: .signing, generation: 1),
            rotationKey: try .init(purpose: .rotation, generation: 1),
            createdAt: Date(timeIntervalSince1970: 1_750_000_000)
        )
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "PLCCredentialKeyContinuitySQLiteTests-\(UUID().uuidString)"
        )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }
}

private func assertThrowsContinuityError<T>(
    _ expression: @autoclosure () async throws -> T,
    _ expected: PLCCredentialKeyContinuityStoreError,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected continuity-store error", file: file, line: line)
    } catch {
        XCTAssertEqual(
            error as? PLCCredentialKeyContinuityStoreError,
            expected,
            file: file,
            line: line
        )
    }
}

private func assertThrowsAccountControlError<T>(
    _ expression: @autoclosure () async throws -> T,
    _ expected: AccountControlStoreError,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected account-control error", file: file, line: line)
    } catch {
        XCTAssertEqual(
            error as? AccountControlStoreError,
            expected,
            file: file,
            line: line
        )
    }
}
