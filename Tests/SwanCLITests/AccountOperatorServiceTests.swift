import Foundation
@testable import SwanAccounts
import PetrelFirehose
import SwanSQLite
import SwanStorage
import XCTest

final class AccountOperatorServiceTests: XCTestCase {
    func testOperatorSecretResolverRejectsMissingAndInvalidSources() throws {
        XCTAssertThrowsError(
            try OperatorSecretResolver.authorize(secretFile: nil)
        ) { error in
            XCTAssertEqual(error as? AccountOperatorError, .operatorSecretMissing)
        }
        XCTAssertThrowsError(
            try OperatorSecretResolver.loadVerifier(secretFile: nil)
        ) { error in
            XCTAssertEqual(error as? AccountOperatorError, .operatorSecretMissing)
        }

        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appending(path: "operator-secret")
        try Data("operator-secret\n".utf8).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        XCTAssertNoThrow(
            try OperatorSecretResolver.authorize(secretFile: file)
        )
        XCTAssertNoThrow(
            try OperatorSecretResolver.loadVerifier(secretFile: file)
        )
    }

    func testOperatorSecretResolverRejectsLinksAndBroadlyReadableFiles() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let secret = root.appending(path: "operator-secret")
        try Data("operator-secret\n".utf8).write(to: secret)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: secret.path)
        let link = root.appending(path: "operator-secret-link")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: secret.path)

        XCTAssertThrowsError(
            try OperatorSecretResolver.authorize(secretFile: link)
        ) { error in
            XCTAssertEqual(error as? AccountOperatorError, .operatorSecretFileUnavailable)
        }

        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: secret.path)
        XCTAssertThrowsError(
            try OperatorSecretResolver.authorize(secretFile: secret)
        ) { error in
            XCTAssertEqual(error as? AccountOperatorError, .operatorSecretFileUnavailable)
        }
    }

    func testOperatorSecretVerifierRejectsWrongMalformedAndOversizedBearerValues() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = try createOperatorSecretFile(root: root, secret: "operator-secret")
        let verifier = try OperatorSecretResolver.loadVerifier(secretFile: file)
        XCTAssertNoThrow(try verifier.authorize(bearerValue: "operator-secret"))
        for value in ["wrong-secret", "", "operator secret", String(repeating: "a", count: 4_097)] {
            XCTAssertThrowsError(try verifier.authorize(bearerValue: value)) { error in
                XCTAssertEqual(error as? AccountOperatorError, .operatorSecretRejected)
                XCTAssertFalse(error.localizedDescription.contains("operator-secret"))
            }
        }
    }

    func testOperatorServiceTransitionsReversibleLifecycle() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            try await createAlice(in: control)

            let service = AccountOperatorService(store: control)
            let secretFile = try createOperatorSecretFile(root: root)
            let authorization = try OperatorSecretResolver.authorize(secretFile: secretFile)

            let shown = try await service.show(.handle("Alice.Example.COM"))
            XCTAssertEqual(shown.did, Self.aliceDID)
            XCTAssertEqual(shown.canonicalHandle, "alice.example.com")
            XCTAssertEqual(shown.status, "active")

            let deactivated = try await service.deactivate(
                did: Self.aliceDID,
                authorization: authorization,
                now: Date(timeIntervalSince1970: 1_750_000_010)
            )
            XCTAssertEqual(deactivated.status, "deactivated")
            let reactivated = try await service.reactivate(
                did: Self.aliceDID,
                authorization: authorization,
                now: Date(timeIntervalSince1970: 1_750_000_020)
            )
            XCTAssertEqual(reactivated.status, "active")
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    func testDeleteInvokesPermanentCoordinatorAndReturnsMinimalSanitizedTerminalView() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            try await createAlice(in: control)
            let now = Date(timeIntervalSince1970: 1_750_000_030)
            let manifest =
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            let terminal = try AccountDeletionTombstone(
                did: Self.aliceDID,
                finalizedAt: Date(timeIntervalSince1970: 1_750_000_031),
                revision: 9,
                tombstone: AccountTombstoneMetadata(
                    declaredAt: now,
                    reason: "operator-request"
                ),
                export: AccountExportMetadata(
                    declaredAt: now,
                    reference: manifest
                )
            )
            let deletion = RecordingPermanentDeletionCoordinator(result: terminal)
            let service = AccountOperatorService(
                store: control,
                permanentDeletionCoordinator: deletion
            )
            let secretFile = try createOperatorSecretFile(root: root)
            let authorization = try OperatorSecretResolver.authorize(secretFile: secretFile)

            let deleted = try await service.delete(
                did: Self.aliceDID,
                tombstoneReason: "operator-request",
                exportReference: manifest,
                authorization: authorization,
                now: now
            )

            let requests = await deletion.recordedRequests()
            XCTAssertEqual(
                requests,
                [
                    .init(
                        did: Self.aliceDID,
                        declaration: AccountLifecycleDeclaration(
                            tombstone: try AccountTombstoneMetadata(
                                declaredAt: now,
                                reason: "operator-request"
                            ),
                            export: try AccountExportMetadata(
                                declaredAt: now,
                                reference: manifest
                            )
                        ),
                        now: now
                    ),
                ]
            )
            XCTAssertEqual(deleted.did, Self.aliceDID)
            XCTAssertEqual(deleted.status, "deleted")
            XCTAssertNil(deleted.canonicalHandle)
            XCTAssertNil(deleted.createdAt)
            XCTAssertNil(deleted.updatedAt)
            XCTAssertEqual(deleted.finalizedAt, terminal.finalizedAt)
            XCTAssertEqual(deleted.tombstone, terminal.tombstone)
            XCTAssertEqual(deleted.export, terminal.export)

            let rendered = try AccountOperatorJSON.render(deleted)
            let object = try XCTUnwrap(
                JSONSerialization.jsonObject(with: rendered) as? [String: Any]
            )
            XCTAssertEqual(
                Set(object.keys),
                Set(["did", "status", "finalizedAt", "tombstone", "export"])
            )
            XCTAssertEqual(object["did"] as? String, Self.aliceDID)
            XCTAssertEqual(object["status"] as? String, "deleted")
            let text = String(decoding: rendered, as: UTF8.self)
            XCTAssertFalse(text.contains("alice.example.com"))
            XCTAssertFalse(text.contains("$argon2id$"))
            XCTAssertFalse(text.contains("signingKey"))
            XCTAssertFalse(text.contains("rotationKey"))
            XCTAssertFalse(text.contains("passwordVerifier"))
            XCTAssertFalse(text.contains("operator-secret"))

            // The coordinator owns all lifecycle mutation. The operator
            // service must never append a generic `.deleted` transition.
            let accountAfterDelegatedDeletion = try await control.account(
                did: Self.aliceDID
            )
            XCTAssertEqual(accountAfterDelegatedDeletion?.status, .active)
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    func testDeleteFailsClosedWithoutPermanentDeletionCapabilityAndLeavesAccountActive() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            try await createAlice(in: control)
            let service = AccountOperatorService(store: control)
            let secretFile = try createOperatorSecretFile(root: root)
            let authorization = try OperatorSecretResolver.authorize(secretFile: secretFile)

            do {
                _ = try await service.delete(
                    did: Self.aliceDID,
                    authorization: authorization,
                    now: Date(timeIntervalSince1970: 1_750_000_030)
                )
                XCTFail("deletion ran without the permanent-deletion capability")
            } catch let error as AccountOperatorError {
                XCTAssertEqual(error, .permanentDeletionUnavailable)
            }
            let accountAfterRejectedDeletion = try await control.account(
                did: Self.aliceDID
            )
            XCTAssertEqual(accountAfterRejectedDeletion?.status, .active)
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    func testOperatorServiceReturnsTypedUnknownAccountFailure() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            let service = AccountOperatorService(store: control)
            let secretFile = try createOperatorSecretFile(root: root)
            let authorization = try OperatorSecretResolver.authorize(secretFile: secretFile)

            do {
                _ = try await service.show(.did(Self.aliceDID))
                XCTFail("unknown account unexpectedly resolved")
            } catch let error as AccountOperatorError {
                XCTAssertEqual(error, .unknownAccount)
            }
            do {
                _ = try await service.deactivate(
                    did: Self.aliceDID,
                    authorization: authorization
                )
                XCTFail("unknown account unexpectedly transitioned")
            } catch let error as AccountOperatorError {
                XCTAssertEqual(error, .unknownAccount)
            }
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    func testExportDeclarationStoresOnlyDigestAndRejectsInactiveAccount() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await control.close() } }
        try await createAlice(in: control)
        let service = AccountOperatorService(store: control)
        let secretFile = try createOperatorSecretFile(root: root)
        let authorization = try OperatorSecretResolver.authorize(secretFile: secretFile)
        let digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

        let declared = try await service.declareExport(
            did: Self.aliceDID,
            manifestReference: digest,
            authorization: authorization,
            now: Date(timeIntervalSince1970: 1_750_000_010)
        )
        XCTAssertEqual(declared.status, "active")
        XCTAssertEqual(declared.export?.reference, digest)
        _ = try await service.deactivate(
            did: Self.aliceDID,
            authorization: authorization
        )
        do {
            _ = try await service.declareExport(
                did: Self.aliceDID,
                manifestReference: digest,
                authorization: authorization
            )
            XCTFail("inactive account accepted an export declaration")
        } catch let error as AccountOperatorError {
            XCTAssertEqual(error, .accountInactive)
        }
    }

    func testDeactivateAndReactivateEmitAccountBatchesAndReactivationSync() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            try await createAlice(in: control)
            let emitter = RecordingLifecycleEmitter()
            let service = AccountOperatorService(
                store: control,
                lifecycleEmitter: emitter
            )
            let secretFile = try createOperatorSecretFile(root: root)
            let authorization = try OperatorSecretResolver.authorize(secretFile: secretFile)

            let deactivated = try await service.deactivate(
                did: Self.aliceDID,
                authorization: authorization,
                now: Date(timeIntervalSince1970: 1_750_000_010)
            )
            XCTAssertEqual(deactivated.status, "deactivated")
            let deactivationPending = try await control.nextPendingLifecycleBatch(
                did: Self.aliceDID
            )
            let deactivationBatch = try XCTUnwrap(deactivationPending)
            XCTAssertEqual(deactivationBatch.items.count, 1)
            XCTAssertEqual(deactivationBatch.items[0].kind, .account)
            let deactivationMaterial = try JSONDecoder().decode(
                PublicFirehoseAccountMaterial.self,
                from: deactivationBatch.items[0].payload
            )
            XCTAssertFalse(deactivationMaterial.active)
            XCTAssertEqual(deactivationMaterial.status, .deactivated)
            _ = try await control.completeLifecycleBatch(
                batchID: deactivationBatch.batchID
            )

            let reactivated = try await service.reactivate(
                did: Self.aliceDID,
                authorization: authorization,
                now: Date(timeIntervalSince1970: 1_750_000_020)
            )
            XCTAssertEqual(reactivated.status, "active")
            let reactivationPending = try await control.nextPendingLifecycleBatch(
                did: Self.aliceDID
            )
            let reactivationBatch = try XCTUnwrap(reactivationPending)
            XCTAssertEqual(reactivationBatch.items.count, 1)
            let reactivationMaterial = try JSONDecoder().decode(
                PublicFirehoseAccountMaterial.self,
                from: reactivationBatch.items[0].payload
            )
            XCTAssertTrue(reactivationMaterial.active)
            XCTAssertNil(reactivationMaterial.status)

            let syncCalls = await emitter.reactivationSyncCalls()
            XCTAssertEqual(syncCalls.count, 1)
            XCTAssertEqual(syncCalls.first?.did, Self.aliceDID)
            XCTAssertEqual(
                syncCalls.first?.now,
                Date(timeIntervalSince1970: 1_750_000_020)
            )
            let operationID = try XCTUnwrap(syncCalls.first?.operationID)
            XCTAssertNotNil(UUID(uuidString: operationID))
            XCTAssertEqual(operationID, UUID(uuidString: operationID)?.uuidString.lowercased())
            XCTAssertEqual(
                reactivationBatch.items[0].sourceKey,
                PublicFirehoseSourceKey.account(did: Self.aliceDID, operationID: operationID)
            )
            let deactivationOperationID = try XCTUnwrap(
                deactivationBatch.items[0].sourceKey.split(separator: "|").last.map(String.init)
            )
            XCTAssertNotNil(UUID(uuidString: deactivationOperationID))
            XCTAssertEqual(
                deactivationOperationID,
                UUID(uuidString: deactivationOperationID)?.uuidString.lowercased()
            )
            XCTAssertEqual(
                deactivationBatch.items[0].sourceKey,
                PublicFirehoseSourceKey.account(did: Self.aliceDID, operationID: deactivationOperationID)
            )
            try await control.close()
        } catch {
            try? await control.close()
            throw error
        }
    }

    private func createAlice(in control: SQLiteControlDatabase) async throws {
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: Self.aliceDID,
                canonicalHandle: "alice.example.com",
                passwordVerifier: testVerifier,
                signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
                rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "swan-cli-tests-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        return root
    }

    private static let aliceDID = "did:plc:abcdefghijklmnopqrstuvwx"
    private func createOperatorSecretFile(root: URL, secret: String = "operator-secret") throws -> URL {
        let file = root.appending(path: "operator-secret-\(UUID().uuidString)")
        try Data((secret + "\n").utf8).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        return file
    }
}

private let testVerifier = "$argon2id$v=19$m=65536,t=3,p=1$bcdefghijklmnopqrstuvw$BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"

private struct PermanentDeletionRequest: Sendable, Equatable {
    let did: String
    let declaration: AccountLifecycleDeclaration
    let now: Date
}

private actor RecordingPermanentDeletionCoordinator:
    AccountPermanentDeletionCoordinating
{
    private let result: AccountDeletionTombstone
    private var requests: [PermanentDeletionRequest] = []

    init(result: AccountDeletionTombstone) {
        self.result = result
    }

    func beginAndResume(
        did: String,
        declaration: AccountLifecycleDeclaration,
        now: Date
    ) async throws -> AccountDeletionTombstone {
        requests.append(
            PermanentDeletionRequest(
                did: did,
                declaration: declaration,
                now: now
            )
        )
        return result
    }

    func recordedRequests() -> [PermanentDeletionRequest] {
        requests
    }
}

private struct RecordedReactivationSync: Sendable, Equatable {
    let did: String
    let operationID: String
    let now: Date
}

private actor RecordingLifecycleEmitter: PublicLifecycleEventEmitting {
    private var reactivationSyncs: [RecordedReactivationSync] = []

    func emitActivation(
        did: String,
        operationID: String,
        plcOperationCID: String,
        handle: String?,
        materialTime: Date,
        now: Date
    ) async throws {}

    func emitRotationIdentity(
        did: String,
        plcOperationCID: String,
        handle: String?,
        materialTime: Date,
        now: Date
    ) async throws {}

    func emitReactivationSync(did: String, operationID: String, now: Date) async throws {
        reactivationSyncs.append(
            RecordedReactivationSync(did: did, operationID: operationID, now: now)
        )
    }

    func emitManualSync(did: String, requestUUID: String, now: Date) async throws {}

    func reactivationSyncCalls() -> [RecordedReactivationSync] {
        reactivationSyncs
    }
}
