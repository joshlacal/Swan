import Crypto
import Foundation
@testable import SwanAccounts
import SwanCore
import XCTest

final class AccountKeyDestructionTests: XCTestCase {
    func testDestroyRemovesEveryGenerationAndAuthenticatedMatchingStagingOnly() async throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appending(path: "keys")
        let store = try FileAccountKeyStore(
            root: root,
            configuration: try configuration()
        )
        let staging = try await store.stagePLCAccountIdentity(
            requestID: "delete-staged-identity",
            canonicalHandle: "delete.example.com",
            pdsOrigin: URL(string: "https://pds.example.com")!,
            repositoryRevision: "3lqby3xuo4k2a"
        )
        let otherStaging = try await store.stagePLCAccountIdentity(
            requestID: "keep-staged-identity",
            canonicalHandle: "keep.example.com",
            pdsOrigin: URL(string: "https://pds.example.com")!,
            repositoryRevision: "3lqby3xuo4k2b"
        )
        let targetReferences = try await createGenerations(
            did: staging.did,
            generations: 1 ... 4,
            in: store,
            marker: 0x20
        )
        let otherReferences = try await createGenerations(
            did: otherStaging.did,
            generations: 1 ... 2,
            in: store,
            marker: 0x60
        )
        // Four generations of signing, rotation and #atproto_kem envelopes.
        XCTAssertEqual(
            try keyEnvelopeFiles(in: root, accountDID: staging.did).count,
            12
        )
        XCTAssertEqual(targetReferences.filter { $0.purpose == .kem }.count, 4)

        let report = try await store.destroyAccountKeyMaterial(
            try AccountKeyDestructionRequest(
                accountDID: staging.did,
                stagingBindings: [
                    AccountKeyDeletionStagingBinding(
                        requestID: staging.requestID,
                        canonicalHandle: staging.canonicalHandle,
                        pdsOrigin: staging.pdsOrigin,
                        repositoryRevision: staging.repositoryRevision
                    ),
                ]
            )
        )
        XCTAssertEqual(report.destroyedEnvelopeCount, targetReferences.count)
        XCTAssertEqual(report.destroyedStagingCount, 1)
        for reference in targetReferences {
            await XCTAssertThrowsErrorAsync(
                try await store.key(for: reference)
            )
            // Removed, not merely unreadable: no purpose is skipped.
            let remaining = try await store.keyIfPresent(for: reference)
            XCTAssertNil(remaining, "\(reference.purpose) generation \(reference.generation)")
        }
        XCTAssertTrue(
            try keyEnvelopeFiles(in: root, accountDID: staging.did).isEmpty
        )
        for reference in otherReferences {
            let key = try await store.key(for: reference)
            XCTAssertEqual(key.count, 32)
        }
        _ = try await AccountKEMKeyProvider(keyStore: store)
            .privateKey(accountDID: otherStaging.did)
        let deletedStaging = try await store.stagedPLCAccountIdentity(
            requestID: staging.requestID,
            canonicalHandle: staging.canonicalHandle,
            pdsOrigin: URL(string: staging.pdsOrigin)!,
            repositoryRevision: staging.repositoryRevision
        )
        XCTAssertNil(deletedStaging)
        let retainedStaging = try await store.stagedPLCAccountIdentity(
            requestID: otherStaging.requestID,
            canonicalHandle: otherStaging.canonicalHandle,
            pdsOrigin: URL(string: otherStaging.pdsOrigin)!,
            repositoryRevision: otherStaging.repositoryRevision
        )
        XCTAssertNotNil(retainedStaging)

        let retry = try await store.destroyAccountKeyMaterial(
            try AccountKeyDestructionRequest(
                accountDID: staging.did,
                stagingBindings: [
                    AccountKeyDeletionStagingBinding(
                        requestID: staging.requestID,
                        canonicalHandle: staging.canonicalHandle,
                        pdsOrigin: staging.pdsOrigin,
                        repositoryRevision: staging.repositoryRevision
                    ),
                ]
            )
        )
        XCTAssertEqual(retry.destroyedEnvelopeCount, 0)
        XCTAssertEqual(retry.destroyedStagingCount, 0)
    }

    func testMismatchedStagingBindingFailsBeforeAnyAccountEnvelopeIsRemoved() async throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let store = try FileAccountKeyStore(
            root: parent.appending(path: "keys"),
            configuration: try configuration()
        )
        let staging = try await store.stagePLCAccountIdentity(
            requestID: "mismatched-staging",
            canonicalHandle: "staging.example.com",
            pdsOrigin: URL(string: "https://pds.example.com")!,
            repositoryRevision: "3lqby3xuo4k2a"
        )
        let unrelatedDID = "did:plc:abcdefghijklmnopqrstuvwx"
        let references = try await createGenerations(
            did: unrelatedDID,
            generations: 1 ... 2,
            in: store,
            marker: 0x10
        )
        await XCTAssertThrowsErrorAsync(
            try await store.destroyAccountKeyMaterial(
                AccountKeyDestructionRequest(
                    accountDID: unrelatedDID,
                    stagingBindings: [
                        try AccountKeyDeletionStagingBinding(
                            requestID: staging.requestID,
                            canonicalHandle: staging.canonicalHandle,
                            pdsOrigin: staging.pdsOrigin,
                            repositoryRevision: staging.repositoryRevision
                        ),
                    ]
                )
            )
        )
        for reference in references {
            let key = try await store.key(for: reference)
            XCTAssertEqual(key.count, 32)
        }
        let retainedStaging = try await store.stagedPLCAccountIdentity(
            requestID: staging.requestID,
            canonicalHandle: staging.canonicalHandle,
            pdsOrigin: URL(string: staging.pdsOrigin)!,
            repositoryRevision: staging.repositoryRevision
        )
        XCTAssertNotNil(retainedStaging)
    }

    func testCorruptTargetEnvelopeFailsClosedBeforeRemovingOtherGenerations() async throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appending(path: "keys")
        let store = try FileAccountKeyStore(
            root: root,
            configuration: try configuration()
        )
        let targetDID = "did:plc:abcdefghijklmnopqrstuvwx"
        let otherDID = "did:plc:bcdefghijklmnopqrstuvwxy"
        let targetReferences = try await createGenerations(
            did: targetDID,
            generations: 1 ... 2,
            in: store,
            marker: 0x20
        )
        let otherReferences = try await createGenerations(
            did: otherDID,
            generations: 1 ... 1,
            in: store,
            marker: 0x70
        )
        let otherReference = try XCTUnwrap(otherReferences.first)
        let targetFiles = try keyEnvelopeFiles(in: root, accountDID: targetDID)
        // Two generations of signing, rotation and #atproto_kem envelopes.
        XCTAssertEqual(targetFiles.count, 6)
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: Data(contentsOf: targetFiles[0])
            ) as? [String: Any]
        )
        let corruptPurpose = try XCTUnwrap(
            (object["purpose"] as? String).flatMap(AccountKeyPurpose.init(rawValue:))
        )
        let corruptGeneration = try XCTUnwrap(
            (object["generation"] as? NSNumber).map(\.uint64Value)
        )
        let corruptReference = try AccountKeyReference(
            accountDID: targetDID,
            purpose: corruptPurpose,
            generation: corruptGeneration
        )
        var sealed = try XCTUnwrap(
            Data(base64Encoded: try XCTUnwrap(object["sealedKey"] as? String))
        )
        sealed[sealed.startIndex] ^= 0x01
        object["sealedKey"] = sealed.base64EncodedString()
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            .write(to: targetFiles[0], options: .atomic)

        await XCTAssertThrowsErrorAsync(
            try await store.destroyAccountKeyMaterial(
                AccountKeyDestructionRequest(
                    accountDID: targetDID,
                    stagingBindings: []
                )
            )
        )
        // The corrupt file itself is deliberately unreadable, but every other
        // target generation and every other DID must remain untouched.
        XCTAssertEqual(
            try keyEnvelopeFiles(in: root, accountDID: targetDID)
                .map(\.lastPathComponent),
            targetFiles.map(\.lastPathComponent)
        )
        for reference in targetReferences where reference != corruptReference {
            let key = try await store.key(for: reference)
            XCTAssertEqual(key.count, 32)
        }
        let otherKey = try await store.key(for: otherReference)
        XCTAssertEqual(otherKey.count, 32)
    }

    /// The October 22 `#atproto_kem` envelope is authenticated before removal
    /// exactly like the signing and rotation envelopes: corrupting any one
    /// purpose aborts destruction before a single file is removed.
    func testCorruptEnvelopeOfEveryPurposeIncludingKEMFailsClosedBeforeAnyRemoval() async throws {
        XCTAssertTrue(AccountKeyPurpose.allCases.contains(.kem))
        for purpose in AccountKeyPurpose.allCases {
            let parent = try temporaryDirectory()
            defer { try? FileManager.default.removeItem(at: parent) }
            let root = parent.appending(path: "keys")
            let store = try FileAccountKeyStore(
                root: root,
                configuration: try configuration()
            )
            let targetDID = "did:plc:abcdefghijklmnopqrstuvwx"
            let otherDID = "did:plc:bcdefghijklmnopqrstuvwxy"
            let targetReferences = try await createGenerations(
                did: targetDID,
                generations: 1 ... 2,
                in: store,
                marker: 0x20
            )
            let otherReferences = try await createGenerations(
                did: otherDID,
                generations: 1 ... 1,
                in: store,
                marker: 0x70
            )
            // Generation one is the KEM key AccountKEMKeyProvider publishes.
            let corruptReference = try AccountKeyReference(
                accountDID: targetDID,
                purpose: purpose,
                generation: 1
            )
            let targetFiles = try keyEnvelopeFiles(in: root, accountDID: targetDID)
            XCTAssertEqual(targetFiles.count, 6, "\(purpose)")
            try corruptSealedKey(
                in: try envelopeFile(for: corruptReference, among: targetFiles)
            )

            await XCTAssertThrowsErrorAsync(
                try await store.destroyAccountKeyMaterial(
                    AccountKeyDestructionRequest(
                        accountDID: targetDID,
                        stagingBindings: []
                    )
                )
            )
            XCTAssertEqual(
                try keyEnvelopeFiles(in: root, accountDID: targetDID)
                    .map(\.lastPathComponent),
                targetFiles.map(\.lastPathComponent),
                "\(purpose): no target envelope may be removed"
            )
            for reference in targetReferences where reference != corruptReference {
                let key = try await store.key(for: reference)
                XCTAssertEqual(key.count, 32, "\(purpose)")
            }
            for reference in otherReferences {
                let key = try await store.key(for: reference)
                XCTAssertEqual(key.count, 32, "\(purpose)")
            }
        }
    }

    private func envelopeFile(
        for reference: AccountKeyReference,
        among files: [URL]
    ) throws -> URL {
        let matches = try files.filter { url in
            let object = try XCTUnwrap(
                JSONSerialization.jsonObject(
                    with: Data(contentsOf: url)
                ) as? [String: Any]
            )
            return object["purpose"] as? String == reference.purpose.rawValue
                && (object["generation"] as? NSNumber)?.uint64Value
                    == reference.generation
        }
        XCTAssertEqual(matches.count, 1)
        return try XCTUnwrap(matches.first)
    }

    private func corruptSealedKey(in file: URL) throws {
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: Data(contentsOf: file)
            ) as? [String: Any]
        )
        var sealed = try XCTUnwrap(
            Data(base64Encoded: try XCTUnwrap(object["sealedKey"] as? String))
        )
        sealed[sealed.startIndex] ^= 0x01
        object["sealedKey"] = sealed.base64EncodedString()
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            .write(to: file, options: .atomic)
    }

    private func createGenerations(
        did: String,
        generations: ClosedRange<Int>,
        in store: FileAccountKeyStore,
        marker: UInt8
    ) async throws -> [AccountKeyReference] {
        var references: [AccountKeyReference] = []
        for generation in generations {
            for purpose in AccountKeyPurpose.allCases {
                let reference = try AccountKeyReference(
                    accountDID: did,
                    purpose: purpose,
                    generation: UInt64(generation)
                )
                try await store.create(
                    Data(
                        repeating: marker
                            &+ UInt8(generation * 2)
                            &+ (purpose == .rotation ? 1 : 0),
                        count: 32
                    ),
                    for: reference
                )
                references.append(reference)
            }
        }
        return references
    }

    private func keyEnvelopeFiles(
        in root: URL,
        accountDID: String
    ) throws -> [URL] {
        try FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "key" }.filter { url in
            guard let object = try? JSONSerialization.jsonObject(
                with: Data(contentsOf: url)
            ) as? [String: Any] else {
                return false
            }
            return object["accountDID"] as? String == accountDID
        }.sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    private func configuration() throws -> AccountKeyEncryptionConfiguration {
        try AccountKeyEncryptionConfiguration(
            activeKeyID: "deletion-test-kek",
            activeKey: Data(repeating: 0xA5, count: 32)
        )
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "swan-key-destruction-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ errorHandler: (any Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("expected expression to throw")
    } catch {
        errorHandler(error)
    }
}
