import Foundation
import SwanPublicFirehose
import SwanStorage
import XCTest

@testable import SwanSQLite

final class AccountAuthorizationLeaseTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let time = "2026-08-04T12:00:00.000Z"

    private func identityItem(did: String) -> LifecycleEventItem {
        let material = PublicFirehoseIdentityMaterial(
            did: did,
            handle: "authorization-lease.example.com",
            time: time
        )
        return LifecycleEventItem(
            sourceKey: PublicFirehoseSourceKey.identity(
                did: did,
                plcOperationCID: "bafyid1"
            ),
            kind: .identity,
            payload: try! JSONEncoder().encode(material),
            carBytes: nil
        )
    }

    func testAuthorizationLeaseSerializesFinalMutationWithActiveLifecycle() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "SwanAccountAuthorizationLease-\(UUID().uuidString)"
            )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await control.close() } }
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: did,
                canonicalHandle: "authorization-lease.example.com",
                passwordVerifier:
                    "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: .init(purpose: .signing, generation: 1),
                rotationKey: .init(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )

        let result = try await control.withActiveAccountAuthorization(
            did: did
        ) {
            let hasLease = await control.hasActiveWriteTransactionForTesting()
            XCTAssertTrue(
                hasLease,
                "the publication callback must run under the control write lease"
            )
            return "published"
        }
        XCTAssertEqual(result, "published")

        _ = try await control.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_001)
        )
        do {
            _ = try await control.withActiveAccountAuthorization(did: did) {
                XCTFail("deactivated accounts must not reach publication")
                return "unreachable"
            }
            XCTFail("expected deactivated authorization to fail")
        } catch let error as AccountControlStoreError {
            XCTAssertEqual(error, .invalidTransition)
        }
    }

    func testFirehoseAuthorizationFencePassesLiveGenerationAndRejectsInactive() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "SwanAccountAuthorizationLease-\(UUID().uuidString)"
            )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await control.close() } }
        _ = try await control.createAccount(
            AccountControlRegistration(
                did: did,
                canonicalHandle: "authorization-lease.example.com",
                passwordVerifier:
                    "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: .init(purpose: .signing, generation: 1),
                rotationKey: .init(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )
        _ = try await control.enqueueLifecycleEventBatch(
            did: did,
            operationID: "op-1",
            items: [identityItem(did: did)],
            now: Date(timeIntervalSince1970: 1_750_000_000)
        )
        let seen = try await control.withActiveAccountFirehoseAuthorization(
            did: did
        ) { generation in
            generation
        }
        XCTAssertEqual(seen, 1)

        _ = try await control.transitionStatus(
            did: did,
            to: .deactivated,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_001)
        )
        do {
            _ = try await control.withActiveAccountFirehoseAuthorization(did: did) { _ in
                XCTFail("deactivated accounts must not reach the firehose generation")
                return true
            }
            XCTFail("expected deactivated firehose authorization to fail")
        } catch let error as AccountControlStoreError {
            guard case .invalidTransition = error else { throw error }
        }
    }
}
