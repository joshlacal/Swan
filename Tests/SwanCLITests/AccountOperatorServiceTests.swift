import Foundation
@testable import SwanAccounts
import SwanSQLite
import SwanStorage
import XCTest

final class AccountOperatorServiceTests: XCTestCase {
    func testOperatorSecretResolverRejectsMissingAndMismatchedSources() throws {
        XCTAssertThrowsError(
            try OperatorSecretResolver.authorize(
                environment: [:],
                secretFile: nil
            )
        ) { error in
            XCTAssertEqual(error as? AccountOperatorError, .operatorSecretMissing)
        }

        let file = try temporaryDirectory().appending(path: "operator-secret")
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
        try Data("operator-secret\n".utf8).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        XCTAssertNoThrow(
            try OperatorSecretResolver.authorize(environment: [:], secretFile: file)
        )
        try Data("not-the-operator-secret\n".utf8).write(to: file)

        XCTAssertThrowsError(
            try OperatorSecretResolver.authorize(
                environment: ["SWAN_OPERATOR_SECRET": "operator-secret"],
                secretFile: file
            )
        ) { error in
            XCTAssertEqual(error as? AccountOperatorError, .operatorSecretRejected)
            XCTAssertFalse(error.localizedDescription.contains("operator-secret"))
            XCTAssertFalse(error.localizedDescription.contains("not-the-operator-secret"))
        }
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
            try OperatorSecretResolver.authorize(environment: [:], secretFile: link)
        ) { error in
            XCTAssertEqual(error as? AccountOperatorError, .operatorSecretFileUnavailable)
        }

        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: secret.path)
        XCTAssertThrowsError(
            try OperatorSecretResolver.authorize(environment: [:], secretFile: secret)
        ) { error in
            XCTAssertEqual(error as? AccountOperatorError, .operatorSecretFileUnavailable)
        }
    }

    func testOperatorSecretVerifierRejectsWrongMalformedAndOversizedBearerValues() throws {
        let verifier = try OperatorSecretResolver.loadVerifier(
            environment: ["SWAN_OPERATOR_SECRET": "operator-secret"],
            secretFile: nil
        )
        XCTAssertNoThrow(try verifier.authorize(bearerValue: "operator-secret"))
        for value in ["wrong-secret", "", "operator secret", String(repeating: "a", count: 4_097)] {
            XCTAssertThrowsError(try verifier.authorize(bearerValue: value)) { error in
                XCTAssertEqual(error as? AccountOperatorError, .operatorSecretRejected)
                XCTAssertFalse(error.localizedDescription.contains("operator-secret"))
            }
        }
    }

    func testOperatorServiceTransitionsLifecycleAndProjectsOnlySanitizedJSON() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        do {
            try await createAlice(in: control)

            let service = AccountOperatorService(store: control)
            let authorization = try OperatorSecretResolver.authorize(
                environment: ["SWAN_OPERATOR_SECRET": "operator-secret"],
                secretFile: nil
            )

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
            let deleted = try await service.delete(
                did: Self.aliceDID,
                tombstoneReason: "operator-request",
                exportReference: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                authorization: authorization,
                now: Date(timeIntervalSince1970: 1_750_000_030)
            )
            XCTAssertEqual(deleted.status, "deleted")
            XCTAssertEqual(deleted.tombstone?.reason, "operator-request")
            XCTAssertEqual(
                deleted.export?.reference,
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )

            let rendered = try AccountOperatorJSON.render(deleted)
            let object = try XCTUnwrap(
                JSONSerialization.jsonObject(with: rendered) as? [String: Any]
            )
            XCTAssertEqual(object["did"] as? String, Self.aliceDID)
            XCTAssertEqual(object["canonicalHandle"] as? String, "alice.example.com")
            XCTAssertEqual(object["status"] as? String, "deleted")
            XCTAssertNotNil(object["tombstone"])
            XCTAssertNotNil(object["export"])
            let text = String(decoding: rendered, as: UTF8.self)
            XCTAssertFalse(text.contains("$argon2id$"))
            XCTAssertFalse(text.contains("signingKey"))
            XCTAssertFalse(text.contains("rotationKey"))
            XCTAssertFalse(text.contains("passwordVerifier"))
            XCTAssertFalse(text.contains("operator-secret"))
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
            let authorization = try OperatorSecretResolver.authorize(
                environment: ["SWAN_OPERATOR_SECRET": "operator-secret"],
                secretFile: nil
            )

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
        return root
    }

    private static let aliceDID = "did:plc:abcdefghijklmnopqrstuvwx"
}

private let testVerifier = "$argon2id$v=19$m=65536,t=3,p=1$bcdefghijklmnopqrstuvw$BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
