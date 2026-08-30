import Crypto
import Dispatch
import Foundation
import SQLiteNIO
import SwanCore
import PetrelCrypto
import PetrelPLC
import SwanSQLite
import SwanStorage
import XCTest
@_spi(ServeStartup) @testable import SwanAccounts

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

final class SwanAccountsTests: XCTestCase {
    func testArgon2idHashVerifyUnicodeNULAndWrongPassword() throws {
        let hasher = try LibsodiumArgon2idHasher()
        let password = "correct\u{0} horse 🦢 батарея"
        let encodedHash = try hasher.hash(password)

        XCTAssertTrue(encodedHash.hasPrefix("$argon2id$v=19$"))
        XCTAssertTrue(try hasher.verify(password, encodedHash: encodedHash))
        XCTAssertFalse(try hasher.verify("correct horse 🦢 батарея", encodedHash: encodedHash))
        XCTAssertFalse(try hasher.needsRehash(encodedHash))
    }

    func testArgon2idRejectsMalformedPHCAndUsesExplicitAlgorithmVersionRehashSemantics() throws {
        let baseline = try LibsodiumArgon2idHasher()
        XCTAssertThrowsError(try baseline.verify("password", encodedHash: "not-a-phc-string"))
        XCTAssertThrowsError(try baseline.needsRehash(
            "$argon2id$v=19$m=65536,m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
        ))

        let encodedHash = try baseline.hash("rehash me")
        let stronger = try LibsodiumArgon2idHasher(policy: Argon2idPolicy(
            operationsLimit: 3,
            memoryLimitBytes: Argon2idPolicy.minimumMemoryLimitBytes
        ))
        XCTAssertTrue(try stronger.needsRehash(encodedHash))
        XCTAssertThrowsError(
            try stronger.verify("rehash me", encodedHash: encodedHash),
            "a restored verifier with a different work factor must fail before Argon2id"
        )

        let argon2i = encodedHash.replacingOccurrences(of: "$argon2id$", with: "$argon2i$")
        let oldVersion = encodedHash.replacingOccurrences(of: "$v=19$", with: "$v=16$")
        let differentParallelism = encodedHash.replacingOccurrences(of: ",p=1$", with: ",p=2$")
        XCTAssertTrue(try baseline.needsRehash(argon2i))
        XCTAssertTrue(try baseline.needsRehash(oldVersion))
        XCTAssertTrue(try baseline.needsRehash(differentParallelism))
        XCTAssertThrowsError(try baseline.verify("rehash me", encodedHash: argon2i))
        XCTAssertThrowsError(try baseline.verify("rehash me", encodedHash: oldVersion))
        XCTAssertThrowsError(try baseline.verify(
            "rehash me",
            encodedHash: differentParallelism
        ))
    }

    func testArgon2idExecutorEnforcesAdmissionBoundOffCooperativePool() async throws {
        let release = DispatchSemaphore(value: 0)
        let executor = try Argon2idVerificationExecutor(
            maximumConcurrentVerifications: 2
        ) { _, _ in
            release.wait()
            return true
        }

        async let first = executor.verify("1", encodedHash: "unused")
        async let second = executor.verify("2", encodedHash: "unused")
        async let third = executor.verify("3", encodedHash: "unused")
        async let fourth = executor.verify("4", encodedHash: "unused")

        try await waitUntil {
            let metrics = await executor.metrics()
            return metrics.active == 2 && metrics.queued == 2
        }
        let saturated = await executor.metrics()
        XCTAssertEqual(saturated.active, 2)
        XCTAssertEqual(saturated.queued, 2)
        XCTAssertEqual(saturated.peakActive, 2)

        for _ in 0 ..< 4 {
            release.signal()
        }
        let results = try await (first, second, third, fourth)
        XCTAssertTrue(results.0 && results.1 && results.2 && results.3)
        let finalMetrics = await executor.metrics()
        XCTAssertEqual(finalMetrics.peakActive, 2)
    }

    func testArgon2idExecutorRejectsOverloadAndNeverAdmitsCancelledQueuedWork() async throws {
        let release = DispatchSemaphore(value: 0)
        let executor = try Argon2idVerificationExecutor(
            maximumConcurrentVerifications: 1,
            maximumQueuedVerifications: 1
        ) { _, _ in
            release.wait()
            return true
        }

        let active = Task { try await executor.verify("active", encodedHash: "unused") }
        try await waitUntil {
            let metrics = await executor.metrics()
            return metrics.active == 1
        }
        let queued = Task { try await executor.verify("queued", encodedHash: "unused") }
        try await waitUntil {
            let metrics = await executor.metrics()
            return metrics.queued == 1
        }

        await XCTAssertThrowsSwanErrorAsync(
            try await executor.verify("rejected", encodedHash: "unused"),
            expected: .unavailable("Argon2id verification capacity exhausted")
        )
        queued.cancel()
        do {
            _ = try await queued.value
            XCTFail("cancelled queued verification unexpectedly completed")
        } catch is CancellationError {
            // Expected: cancellation removed this request before admission.
        }
        try await waitUntil {
            let metrics = await executor.metrics()
            return metrics.queued == 0
        }

        release.signal()
        let activeResult = try await active.value
        XCTAssertTrue(activeResult)
        let metrics = await executor.metrics()
        XCTAssertEqual(metrics.totalAdmitted, 1)
        XCTAssertEqual(metrics.totalRejected, 1)
        XCTAssertEqual(metrics.active, 0)
        XCTAssertEqual(metrics.queued, 0)
    }

    func testCanonicalIdentifiersAndNormalizedHandleDuplicates() async throws {
        let account = try SwanAccount(
            did: Self.aliceDID,
            handle: "Alice.Example.COM"
        )
        XCTAssertEqual(account.did, Self.aliceDID)
        XCTAssertEqual(account.handle, "alice.example.com")

        let directory = InMemoryAccountDirectory()
        try await directory.create(account)
        let duplicate = try SwanAccount(
            did: Self.bobDID,
            handle: "ALICE.example.COM"
        )
        await XCTAssertThrowsSwanErrorAsync(
            try await directory.create(duplicate),
            expected: .conflict(expected: 0, actual: 1)
        )
        let resolved = await directory.resolve(handle: "Alice.Example.Com")
        XCTAssertEqual(resolved?.did, account.did)

        XCTAssertEqual(try AccountIdentifiers.validateDID(Self.aliceDID), Self.aliceDID)
        XCTAssertEqual(
            try AccountIdentifiers.validateDID("did:web:example.com%3A443:user:Alice"),
            "did:web:example.com%3A443:user:Alice"
        )
        for did in [
            "DID:plc:abcdefghijklmnopqrstuvwx",
            "did:PLC:abcdefghijklmnopqrstuvwx",
            "did:plc:",
            "did:plc:ali ce",
            "did:plc:abcdefghijklmnopqrstuvw0",
            "did:plc:abcdefghijklmnopqrstuvWX",
            "did:key:abcdefghijklmnopqrstuvwx",
            "did:web:example.com%3a443",
            "did:web:Example.com",
            "did:web:example.com:%61",
        ] {
            XCTAssertThrowsError(try AccountIdentifiers.validateDID(did), did)
        }
        for handle in [
            "singlelabel",
            "alice..example.com",
            "-alice.example.com",
            "alice.example.123",
            "alice.3com",
            "álîce.example.com",
            "alice.example.com\u{0}",
        ] {
            XCTAssertThrowsError(try AccountIdentifiers.canonicalHandle(handle), handle)
        }
        XCTAssertThrowsError(try AccountKeyReference(
            accountDID: "did:PLC:abcdefghijklmnopqrstuvwx",
            purpose: .signing,
            generation: 1
        ))

        let invalidAccount = Data(
            #"{"did":"did:PLC:abcdefghijklmnopqrstuvwx","handle":"alice.example.com","status":"active","createdAt":0}"#.utf8
        )
        XCTAssertThrowsError(try JSONDecoder().decode(SwanAccount.self, from: invalidAccount))
        let invalidReference = Data(
            #"{"accountDID":"did:PLC:abcdefghijklmnopqrstuvwx","purpose":"account-signing","generation":1}"#.utf8
        )
        XCTAssertThrowsError(try JSONDecoder().decode(AccountKeyReference.self, from: invalidReference))
    }

    func testEnvelopeAADRejectsDIDPurposeAndGenerationSwapsWithAuthenticationError() async throws {
        let original = try keyReference()
        let swaps = [
            try AccountKeyReference(accountDID: Self.bobDID, purpose: .signing, generation: 1),
            try AccountKeyReference(accountDID: Self.aliceDID, purpose: .rotation, generation: 1),
            try AccountKeyReference(accountDID: Self.aliceDID, purpose: .signing, generation: 2),
        ]

        for swap in swaps {
            let root = try temporaryDirectory()
            defer { try? FileManager.default.removeItem(at: root) }
            let store = try FileAccountKeyStore(
                root: root,
                configuration: keyConfiguration(activeKeyID: "active", byte: 7)
            )
            try await store.create(Data(repeating: 1, count: 32), for: original)
            let originalFile = try onlyKeyFile(in: root)
            let originalEnvelope = try Data(contentsOf: originalFile)

            try await store.create(Data(repeating: 2, count: 32), for: swap)
            let targetFile = try Set(keyFiles(in: root)).subtracting([originalFile]).onlyElement()
            try writeEnvelope(
                originalEnvelope,
                replacing: [
                    "accountDID": swap.accountDID,
                    "purpose": swap.purpose.rawValue,
                    "generation": NSNumber(value: swap.generation),
                ],
                to: targetFile
            )

            await XCTAssertThrowsSwanErrorAsync(
                try await store.key(for: swap),
                expected: .unauthorized("account key envelope authentication failed")
            )
        }
    }

    func testExistingFileKeyReaderReadsWithoutCreatingOrMutatingStore() async throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appending(path: "keys")
        let configuration = try keyConfiguration(activeKeyID: "active", byte: 23)
        let reference = try keyReference()
        let expectedKey = Data(repeating: 0x5A, count: 32)

        let writer = try FileAccountKeyStore(root: root, configuration: configuration)
        try await writer.create(expectedKey, for: reference)
        let before = try keyStoreSnapshot(root)

        var reader: ExistingFileAccountKeyReader? = try ExistingFileAccountKeyReader(
            root: root,
            configuration: configuration
        )
        let actualKey = try await reader?.key(for: reference)
        XCTAssertEqual(actualKey, expectedKey)
        reader = nil

        XCTAssertEqual(try keyStoreSnapshot(root), before)

        let missing = parent.appending(path: "missing-keys")
        XCTAssertThrowsError(try ExistingFileAccountKeyReader(
            root: missing,
            configuration: configuration
        ))
        XCTAssertFalse(FileManager.default.fileExists(atPath: missing.path))
    }

    func testPublicKeyMetadataIsAuthenticatedWithoutReadingPrivateMaterial() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let reference = try keyReference()
        let signingKey = P256.Signing.PrivateKey()
        let store = try FileAccountKeyStore(
            root: root,
            configuration: keyConfiguration(activeKeyID: "active", byte: 17)
        )
        try await store.create(signingKey.rawRepresentation, for: reference)

        let storedPublicKey = try await store.publicKey(for: reference)
        let publicKey = try XCTUnwrap(storedPublicKey)
        XCTAssertEqual(publicKey, signingKey.publicKey.x963Representation)

        let keyFile = try onlyKeyFile(in: root)
        var envelope = try envelopeObject(Data(contentsOf: keyFile))
        envelope["publicKey"] = P256.Signing.PrivateKey()
            .publicKey
            .x963Representation
            .base64EncodedString()
        try writeEnvelope(envelope, to: keyFile)
        await XCTAssertThrowsSwanErrorAsync(
            try await store.publicKey(for: reference),
            expected: .unauthorized("account key public metadata authentication failed")
        )
    }

    func testEnvelopeCiphertextKIDAndFormatTamperingHaveConcreteFailureCategories() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let configuration = try AccountKeyEncryptionConfiguration(
            activeKeyID: "active",
            activeKey: Data(repeating: 1, count: 32),
            decryptOnlyKeys: ["old": Data(repeating: 2, count: 32)]
        )
        let reference = try keyReference()

        do {
            let store = try FileAccountKeyStore(root: root, configuration: configuration)
            try await store.create(Data(repeating: 3, count: 32), for: reference)
            let keyFile = try onlyKeyFile(in: root)
            var object = try envelopeObject(Data(contentsOf: keyFile))
            var ciphertext = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(object["sealedKey"] as? String)))
            ciphertext[ciphertext.startIndex] ^= 0x01
            object["sealedKey"] = ciphertext.base64EncodedString()
            try writeEnvelope(object, to: keyFile)
            await XCTAssertThrowsSwanErrorAsync(
                try await store.key(for: reference),
                expected: .unauthorized("account key envelope authentication failed")
            )
        }

        try FileManager.default.removeItem(at: try onlyKeyFile(in: root))
        do {
            let store = try FileAccountKeyStore(root: root, configuration: configuration)
            try await store.create(Data(repeating: 3, count: 32), for: reference)
            let keyFile = try onlyKeyFile(in: root)
            try writeEnvelope(
                Data(contentsOf: keyFile),
                replacing: ["kid": "old"],
                to: keyFile
            )
            await XCTAssertThrowsSwanErrorAsync(
                try await store.key(for: reference),
                expected: .unauthorized("account key envelope authentication failed")
            )
        }

        try FileManager.default.removeItem(at: try onlyKeyFile(in: root))
        do {
            let store = try FileAccountKeyStore(root: root, configuration: configuration)
            try await store.create(Data(repeating: 3, count: 32), for: reference)
            let keyFile = try onlyKeyFile(in: root)
            try writeEnvelope(
                Data(contentsOf: keyFile),
                replacing: ["format": "swan-key-envelope-v2"],
                to: keyFile
            )
            await XCTAssertThrowsSwanErrorAsync(
                try await store.key(for: reference),
                expected: .malformed("account key envelope format mismatch")
            )
        }
    }

    func testDescriptorAnchoringResistsRootReplacementAndBoundsReads() async throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appending(path: "keys")
        let movedRoot = parent.appending(path: "pinned-keys")
        let hostileRoot = parent.appending(path: "hostile")
        let store = try FileAccountKeyStore(
            root: root,
            configuration: keyConfiguration(activeKeyID: "active", byte: 9)
        )
        XCTAssertEqual(try permissions(of: root), 0o700)
        XCTAssertEqual(
            try permissions(of: root.appending(path: ".swan-key-store.lock")),
            0o600
        )
        XCTAssertEqual(
            try permissions(of: root.appending(path: ".swan-active-kek-v1")),
            0o600
        )
        try await store.create(Data(repeating: 8, count: 32), for: keyReference())

        try FileManager.default.moveItem(at: root, to: movedRoot)
        try FileManager.default.createDirectory(at: hostileRoot, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: root, withDestinationURL: hostileRoot)
        let secondReference = try AccountKeyReference(
            accountDID: Self.aliceDID,
            purpose: .rotation,
            generation: 1
        )
        try await store.create(Data(repeating: 7, count: 32), for: secondReference)

        XCTAssertEqual(try keyFiles(in: movedRoot).count, 2)
        XCTAssertTrue(try keyFiles(in: hostileRoot).isEmpty)
        XCTAssertEqual(try permissions(of: movedRoot), 0o700)
        for keyFile in try keyFiles(in: movedRoot) {
            XCTAssertEqual(try permissions(of: keyFile), 0o600)
        }

        for keyFile in try keyFiles(in: movedRoot) {
            try Data(repeating: 0, count: 16 * 1_024 + 1).write(to: keyFile)
        }
        await XCTAssertThrowsSwanErrorAsync(
            try await store.key(for: try keyReference()),
            expected: .malformed("account key-store entry failed validation")
        )

        let symlinkRoot = parent.appending(path: "symlink-root")
        try FileManager.default.createSymbolicLink(at: symlinkRoot, withDestinationURL: hostileRoot)
        XCTAssertThrowsError(try FileAccountKeyStore(
            root: symlinkRoot,
            configuration: keyConfiguration(activeKeyID: "active", byte: 9)
        ))
    }

    func testDescriptorBackedExistingRootPinsValidatedInodeAcrossPathSwap() async throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appending(path: "keys")
        let movedRoot = parent.appending(path: "pinned-keys")
        let replacementRoot = parent.appending(path: "replacement")
        let reference = try keyReference()
        let secondReference = try AccountKeyReference(
            accountDID: Self.aliceDID,
            purpose: .rotation,
            generation: 1
        )
        let configuration = try keyConfiguration(activeKeyID: "active", byte: 41)

        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let descriptor = root.withUnsafeFileSystemRepresentation { path in
            guard let path else { return Int32(-1) }
            return open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        defer {
            if descriptor >= 0 { _ = close(descriptor) }
        }

        // This is the exact startup ordering: validate/open the root first,
        // then let an attacker rename it and install a replacement at the
        // original pathname before the store is initialized.
        try FileManager.default.moveItem(at: root, to: movedRoot)
        try FileManager.default.createDirectory(
            at: replacementRoot,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )

        let store = try FileAccountKeyStore(
            existingRootDirectoryDescriptor: descriptor,
            configuration: configuration
        )
        try await store.create(Data(repeating: 1, count: 32), for: reference)

        XCTAssertEqual(try keyFiles(in: movedRoot).count, 1)
        XCTAssertTrue(try keyFiles(in: root).isEmpty)
        XCTAssertTrue(try keyFiles(in: replacementRoot).isEmpty)

        // Repeat the swap with a symlink. All marker, journal, and envelope
        // operations must remain relative to the pinned inode and must never
        // follow or create content below the replacement pathname.
        try FileManager.default.removeItem(at: root)
        try FileManager.default.createSymbolicLink(
            at: root,
            withDestinationURL: replacementRoot
        )
        try await store.create(Data(repeating: 2, count: 32), for: secondReference)

        XCTAssertEqual(try keyFiles(in: movedRoot).count, 2)
        XCTAssertTrue(try keyFiles(in: replacementRoot).isEmpty)
        XCTAssertEqual(
            try Data(contentsOf: movedRoot.appending(path: ".swan-active-kek-v1")),
            Data("active".utf8)
        )
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: replacementRoot.appending(path: ".swan-active-kek-v1").path
            )
        )
    }

    func testKeyStoreRejectsUnreadablePrivateKeySizesBeforeInstallation() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try FileAccountKeyStore(
            root: root,
            configuration: keyConfiguration(activeKeyID: "active", byte: 10)
        )
        let reference = try keyReference()

        for count in [31, 33] {
            await XCTAssertThrowsSwanErrorAsync(
                try await store.create(Data(repeating: 1, count: count), for: reference),
                expected: .malformed("P-256 private key material must be exactly 32 bytes")
            )
            XCTAssertThrowsError(try AccountKeyMaterial(
                reference: reference,
                key: Data(repeating: 1, count: count)
            ))
        }
        XCTAssertTrue(try keyFiles(in: root).isEmpty)
    }

    func testDirectoryIterationErrorIsNotMistakenForEndOfInventory() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let configuration = try keyConfiguration(activeKeyID: "active", byte: 13)
        let writer = try FileAccountKeyStore(root: root, configuration: configuration)
        try await writer.create(Data(repeating: 1, count: 32), for: keyReference())

        let faultedReader = try FileAccountKeyStore(
            root: root,
            configuration: configuration,
            failDirectoryIterationAfterEntryCount: 0
        )
        await XCTAssertThrowsSwanErrorAsync(
            try await faultedReader.inventory(),
            expected: .unavailable("could not inventory account key-store directory")
        )
    }

    func testEagerKEKMigrationCoversDormantEnvelopesAndEnablesRetirement() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let oldKey = Data(repeating: 3, count: 32)
        let newKey = Data(repeating: 4, count: 32)
        let references = [
            try keyReference(),
            try AccountKeyReference(
                accountDID: Self.aliceDID,
                purpose: .rotation,
                generation: 1
            ),
        ]
        let oldStore = try FileAccountKeyStore(
            root: root,
            configuration: try AccountKeyEncryptionConfiguration(
                activeKeyID: "old",
                activeKey: oldKey
            )
        )
        for (index, reference) in references.enumerated() {
            try await oldStore.create(Data(repeating: UInt8(index + 1), count: 32), for: reference)
        }

        let rotatingStore = try FileAccountKeyStore(
            root: root,
            configuration: try AccountKeyEncryptionConfiguration(
                activeKeyID: "new",
                activeKey: newKey,
                decryptOnlyKeys: ["old": oldKey]
            )
        )
        let before = try await rotatingStore.inventory()
        XCTAssertEqual(before.writerKeyID, "old")
        XCTAssertEqual(before.envelopeCountByKeyID, ["old": 2])
        XCTAssertFalse(before.isMigrationComplete)

        let report = try await rotatingStore.migrateAllEnvelopesToActiveKey()
        XCTAssertEqual(report.migratedEnvelopeCount, 2)
        XCTAssertEqual(report.inventory.writerKeyID, "new")
        XCTAssertEqual(report.inventory.envelopeCountByKeyID, ["new": 2])
        XCTAssertTrue(report.inventory.isMigrationComplete)

        let retiredStore = try FileAccountKeyStore(
            root: root,
            configuration: try AccountKeyEncryptionConfiguration(
                activeKeyID: "new",
                activeKey: newKey
            )
        )
        for reference in references {
            let key = try await retiredStore.key(for: reference)
            XCTAssertEqual(key.count, 32)
        }

        XCTAssertThrowsError(try AccountKeyEncryptionConfiguration(
            activeKeyID: "new",
            activeKey: newKey,
            decryptOnlyKeys: ["old": newKey]
        ))
    }

    func testPersistentActiveKEKMarkerRejectsStaleAndPrematureWritersAcrossStores() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let oldKey = Data(repeating: 5, count: 32)
        let newKey = Data(repeating: 6, count: 32)
        let oldStore = try FileAccountKeyStore(
            root: root,
            configuration: try AccountKeyEncryptionConfiguration(
                activeKeyID: "old",
                activeKey: oldKey
            )
        )
        try await oldStore.create(Data(repeating: 1, count: 32), for: keyReference())

        let rotatingStore = try FileAccountKeyStore(
            root: root,
            configuration: try AccountKeyEncryptionConfiguration(
                activeKeyID: "new",
                activeKey: newKey,
                decryptOnlyKeys: ["old": oldKey]
            )
        )
        let nextReference = try AccountKeyReference(
            accountDID: Self.aliceDID,
            purpose: .signing,
            generation: 2
        )
        await XCTAssertThrowsSwanErrorAsync(
            try await rotatingStore.create(
                Data(repeating: 2, count: 32),
                for: nextReference
            ),
            expected: .unavailable(
                "active KEK migration is required before writing account keys"
            )
        )

        _ = try await rotatingStore.migrateAllEnvelopesToActiveKey()
        await XCTAssertThrowsSwanErrorAsync(
            try await oldStore.create(Data(repeating: 2, count: 32), for: nextReference),
            expected: .unavailable(
                "active KEK migration is required before writing account keys"
            )
        )
        try await rotatingStore.create(Data(repeating: 2, count: 32), for: nextReference)
        let inventory = try await rotatingStore.inventory()
        XCTAssertEqual(inventory.writerKeyID, "new")
        XCTAssertEqual(inventory.envelopeCountByKeyID, ["new": 2])
        XCTAssertTrue(inventory.isMigrationComplete)
        XCTAssertEqual(
            try String(
                contentsOf: root.appending(path: ".swan-active-kek-v1"),
                encoding: .utf8
            ),
            "new"
        )
    }

    func testRetiringOldKEKBeforeInventoryMigrationFailsClosed() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let oldStore = try FileAccountKeyStore(
            root: root,
            configuration: keyConfiguration(activeKeyID: "old", byte: 3)
        )
        try await oldStore.create(Data(repeating: 1, count: 32), for: keyReference())

        let prematurelyRetired = try FileAccountKeyStore(
            root: root,
            configuration: keyConfiguration(activeKeyID: "new", byte: 4)
        )
        let inventory = try await prematurelyRetired.inventory()
        XCTAssertEqual(inventory.envelopeCountByKeyID, ["old": 1])
        XCTAssertFalse(inventory.isMigrationComplete)
        await XCTAssertThrowsSwanErrorAsync(
            try await prematurelyRetired.migrateAllEnvelopesToActiveKey(),
            expected: .unavailable(
                "active account KEK migration requires the currently active KEK"
            )
        )
    }

    func testProvisioningIsCreateOnlyAndRotationRequiresHigherGeneration() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try FileAccountKeyStore(
            root: root,
            configuration: keyConfiguration(activeKeyID: "active", byte: 11)
        )
        let provisioner = AccountKeyProvisioner(keyStore: store)
        let provisioned = try await provisioner.provisionInitial(accountDID: Self.aliceDID)
        let originalSigning = try await store.key(for: provisioned.signingReference)
        let originalRotation = try await store.key(for: provisioned.rotationReference)

        let resumed = try await provisioner.provisionInitial(accountDID: Self.aliceDID)
        XCTAssertEqual(resumed, provisioned)
        let duplicateSigning = try await store.key(for: provisioned.signingReference)
        let duplicateRotation = try await store.key(for: provisioned.rotationReference)
        XCTAssertEqual(duplicateSigning, originalSigning)
        XCTAssertEqual(duplicateRotation, originalRotation)

        await XCTAssertThrowsSwanErrorAsync(
            try await provisioner.provisionRotation(
                accountDID: Self.aliceDID,
                generation: 1
            ),
            expected: .malformed("account key rotation requires an explicit higher generation")
        )
        let rotated = try await provisioner.provisionRotation(
            accountDID: Self.aliceDID,
            generation: 2
        )
        XCTAssertEqual(rotated.signingReference.generation, 2)
        XCTAssertEqual(rotated.rotationReference.generation, 2)
        let rotatedSigning = try await store.key(for: rotated.signingReference)
        XCTAssertNotEqual(rotatedSigning, originalSigning)
    }

    func testResumeProvisioningRejectsStoredNonP256Scalars() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = try FileAccountKeyStore(
            root: root,
            configuration: keyConfiguration(activeKeyID: "active", byte: 14)
        )
        let signing = try keyReference()
        let rotation = try AccountKeyReference(
            accountDID: Self.aliceDID,
            purpose: .rotation,
            generation: 1
        )
        try await store.create(Data(repeating: 0, count: 32), for: signing)
        try await store.create(Data(repeating: 1, count: 32), for: rotation)

        let provisioner = AccountKeyProvisioner(keyStore: store)
        await XCTAssertThrowsSwanErrorAsync(
            try await provisioner.resumeProvisioning(
                accountDID: Self.aliceDID,
                generation: 1
            ),
            expected: .malformed(
                "stored account provisioning key is not a valid P-256 private key"
            )
        )
    }

    func testInterruptedSecondProvisioningWriteRecoversFromDurableJournal() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let configuration = try keyConfiguration(activeKeyID: "active", byte: 12)
        let interruptedStore = try FileAccountKeyStore(
            root: root,
            configuration: configuration,
            failAfterBatchInstallCount: 1
        )
        let provisioner = AccountKeyProvisioner(keyStore: interruptedStore)
        await XCTAssertThrowsSwanErrorAsync(
            try await provisioner.provisionInitial(accountDID: Self.aliceDID),
            expected: .unavailable("injected account key provisioning interruption")
        )
        XCTAssertEqual(try keyFiles(in: root).count, 1)
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: root.appending(path: ".swan-key-provisioning-journal-v1").path
            )
        )

        let recoveredStore = try FileAccountKeyStore(
            root: root,
            configuration: configuration
        )
        let signing = try keyReference()
        let rotation = try AccountKeyReference(
            accountDID: Self.aliceDID,
            purpose: .rotation,
            generation: 1
        )
        let signingKey = try await recoveredStore.key(for: signing)
        let rotationKey = try await recoveredStore.key(for: rotation)
        XCTAssertNotEqual(signingKey, rotationKey)
        let recoveredProvisioner = AccountKeyProvisioner(keyStore: recoveredStore)
        let resumed = try await recoveredProvisioner.resumeProvisioning(
            accountDID: Self.aliceDID,
            generation: 1
        )
        XCTAssertEqual(resumed.signingReference, signing)
        XCTAssertEqual(resumed.rotationReference, rotation)
        XCTAssertEqual(resumed.signingPublicKey.count, 65)
        XCTAssertEqual(resumed.rotationPublicKey.count, 65)
        XCTAssertNotEqual(resumed.signingPublicKey, resumed.rotationPublicKey)
        let retried = try await recoveredProvisioner.provisionInitial(
            accountDID: Self.aliceDID
        )
        XCTAssertEqual(retried, resumed)
        XCTAssertEqual(try keyFiles(in: root).count, 2)
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: root.appending(path: ".swan-key-provisioning-journal-v1").path
            )
        )
    }

    func testLifecycleStatusIsCanonicalForwardCompatibleAndOnlyActiveIsActive() throws {
        XCTAssertTrue(AccountStatus.active.isActive)
        for status in [
            AccountStatus.deactivated,
            .deleted,
            .takendown,
            .suspended,
            .desynchronized,
            .throttled,
            .unknown("future-moderation-state"),
            .unknown("active"),
        ] {
            XCTAssertFalse(status.isActive)
        }

        let encoded = try JSONEncoder().encode(AccountStatus.unknown("future-moderation-state"))
        XCTAssertEqual(
            try JSONDecoder().decode(AccountStatus.self, from: encoded),
            .unknown("future-moderation-state")
        )
        XCTAssertEqual(
            try JSONDecoder().decode(AccountStatus.self, from: Data(#""active""#.utf8)),
            .active
        )
        XCTAssertThrowsError(try JSONEncoder().encode(AccountStatus.unknown("active")))
        XCTAssertThrowsError(try JSONEncoder().encode(AccountStatus.unknown("ACTIVE")))
        XCTAssertThrowsError(try AccountStatus(rawValue: "future status"))

        for known in [
            AccountStatus.active, .deactivated, .deleted, .takendown,
            .suspended, .desynchronized, .throttled,
        ] {
            let alias = AccountStatus.unknown(known.rawValue)
            XCTAssertFalse(alias.isCanonicalValue)
            XCTAssertThrowsError(try JSONEncoder().encode(alias))
            XCTAssertThrowsError(try SwanAccount(
                did: Self.aliceDID,
                handle: "alice.example.com",
                status: alias
            ))
        }
    }

    func testDurableDirectoryAuthenticatesOnlyActiveAccountsAndKeepsVerifierPrivate() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }
        let hasher = DirectoryTestHasher()
        let executor = try Argon2idVerificationExecutor(
            maximumConcurrentVerifications: 1
        ) { password, verifier in
            password == "correct horse" && DirectoryTestHasher.acceptedVerifiers.contains(verifier)
        }
        let directory = DurableAccountDirectory(
            store: database,
            passwordHasher: hasher,
            verificationExecutor: executor
        )
        let signing = try AccountKeyReference(
            accountDID: Self.aliceDID,
            purpose: .signing,
            generation: 1
        )
        let rotation = try AccountKeyReference(
            accountDID: Self.aliceDID,
            purpose: .rotation,
            generation: 1
        )
        _ = try await database.createAccount(
            AccountControlRegistration(
                did: Self.aliceDID,
                canonicalHandle: "alice.example.com",
                passwordVerifier: DirectoryTestHasher.currentVerifier,
                signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
                rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1),
                createdAt: Date(timeIntervalSince1970: 1_750_000_000)
            )
        )

        let normalLookupResult = try await directory.resolve(handle: "Alice.Example.COM")
        let normalLookup = try XCTUnwrap(normalLookupResult)
        XCTAssertEqual(normalLookup.credentialState, .configured)
        XCTAssertFalse(String(describing: normalLookup).contains(DirectoryTestHasher.currentVerifier))
        let authenticationResult = await directory.authenticate(
            handle: "alice.example.com",
            password: "correct horse"
        )
        let success = try XCTUnwrap(authenticationResult)
        XCTAssertFalse(success.credentialWasRehashed)
        XCTAssertEqual(success.account.did, Self.aliceDID)
        let currentCredential = try await database.credential(did: Self.aliceDID)?.verifier
        XCTAssertEqual(currentCredential, DirectoryTestHasher.currentVerifier)
        let wrongPassword = await directory.authenticate(handle: "alice.example.com", password: "wrong")
        let unknownAccount = await directory.authenticate(handle: "missing.example.com", password: "correct horse")
        let malformedHandle = await directory.authenticate(handle: "invalid handle", password: "correct horse")
        XCTAssertNil(wrongPassword)
        XCTAssertNil(unknownAccount)
        XCTAssertNil(malformedHandle)

        let deactivated = try await directory.transitionStatus(
            did: Self.aliceDID,
            to: .deactivated
        )
        XCTAssertEqual(deactivated.status, .deactivated)
        let deactivatedAuthentication = await directory.authenticate(
            handle: "alice.example.com",
            password: "correct horse"
        )
        XCTAssertNil(deactivatedAuthentication)
        let reactivated = try await directory.transitionStatus(did: Self.aliceDID, to: .active)
        XCTAssertEqual(reactivated.status, .active)
        let reactivatedAuthentication = await directory.authenticate(
            handle: "alice.example.com",
            password: "correct horse"
        )
        XCTAssertNotNil(reactivatedAuthentication)

        for status in [AccountControlStatus.suspended, .takendown, .desynchronized, .throttled,
                       .unknown("future-moderation-state")] {
            _ = try await directory.transitionStatus(did: Self.aliceDID, to: status)
            let authentication = await directory.authenticate(
                handle: "alice.example.com",
                password: "correct horse"
            )
            XCTAssertNil(authentication, "\(status.rawValue) must fail closed")
        }
        _ = try await directory.transitionStatus(did: Self.aliceDID, to: .active)
        await XCTAssertThrowsErrorAsync(
            try await directory.transitionStatus(
                did: Self.aliceDID,
                to: .deleted,
                declaration: AccountLifecycleDeclaration(
                    tombstone: try AccountTombstoneMetadata(
                        reason: "user-request"
                    )
                )
            )
        ) { error in
            XCTAssertEqual(error as? AccountControlStoreError, .invalidTransition)
        }
        let authenticationAfterRejectedGenericDeletion =
            await directory.authenticate(
                handle: "alice.example.com",
                password: "correct horse"
            )
        XCTAssertNotNil(authenticationAfterRejectedGenericDeletion)

        let keyReferencesResult = try await directory.keyReferences(did: Self.aliceDID)
        let references = try XCTUnwrap(keyReferencesResult)
        XCTAssertEqual(references.signing, signing)
        XCTAssertEqual(references.rotation, rotation)
    }

    func testDurableAuthenticationFailsClosedWhenAnotherControlConnectionSuspendsBeforeFinalization() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let first = try await SQLiteControlDatabase(dataDirectory: root)
        let second = try await SQLiteControlDatabase(dataDirectory: root)
        let barrier = AuthenticationFinalizationBarrier()
        let directory = DurableAccountDirectory(
            store: FinalizationGatedAccountControlStore(base: first, barrier: barrier),
            passwordHasher: DirectoryTestHasher(),
            verificationExecutor: try Argon2idVerificationExecutor(
                maximumConcurrentVerifications: 1
            ) { password, verifier in
                password == "correct horse" && verifier == DirectoryTestHasher.currentVerifier
            }
        )
        _ = try await first.createAccount(
            AccountControlRegistration(
                did: Self.aliceDID,
                canonicalHandle: "alice.example.com",
                passwordVerifier: DirectoryTestHasher.currentVerifier,
                signingKey: try AccountControlKeyReference(purpose: .signing, generation: 1),
                rotationKey: try AccountControlKeyReference(purpose: .rotation, generation: 1)
            )
        )

        let authentication = Task {
            await directory.authenticate(handle: "alice.example.com", password: "correct horse")
        }
        await barrier.waitUntilEntered()
        let suspended = try await second.transitionStatus(
            did: Self.aliceDID,
            to: .suspended,
            declaration: .init(),
            now: Date(timeIntervalSince1970: 1_750_000_001)
        )
        XCTAssertEqual(suspended.status, .suspended)
        await barrier.release()

        let result = await authentication.value
        XCTAssertNil(result)
        let finalAccount = try await second.account(did: Self.aliceDID)
        XCTAssertEqual(finalAccount?.status, .suspended)
        try await first.close()
        try await second.close()
    }

    func testDurableDirectoryRejectsInvalidIdentifiersBeforeStorageAndRecordsExternalKeyReferencesOnly() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await database.close() } }
        let keyRoot = root.appending(path: "keys")
        let keyStore = try FileAccountKeyStore(
            root: keyRoot,
            configuration: keyConfiguration(activeKeyID: "active", byte: 21)
        )
        let directory = DurableAccountDirectory(
            store: database,
            passwordHasher: DirectoryTestHasher(),
            verificationExecutor: try Argon2idVerificationExecutor(
                maximumConcurrentVerifications: 1
            ) { _, _ in false },
            keyProvisioner: AccountKeyProvisioner(keyStore: keyStore)
        )
        await XCTAssertThrowsSwanErrorAsync(
            try await directory.provision(
                did: "did:PLC:abcdefghijklmnopqrstuvwx",
                handle: "alice.example.com",
                password: "correct horse"
            ),
            expected: .invalidIdentifier("unsupported account DID method")
        )
        await XCTAssertThrowsSwanErrorAsync(
            try await directory.provision(
                did: Self.aliceDID,
                handle: "singlelabel",
                password: "correct horse"
            ),
            expected: .invalidIdentifier("account handle")
        )

        let account = try await directory.provision(
            did: Self.aliceDID,
            handle: "Alice.Example.COM",
            password: "correct horse"
        )
        XCTAssertEqual(account.canonicalHandle, "alice.example.com")
        let provisionedReferences = try await directory.keyReferences(did: Self.aliceDID)
        let references = try XCTUnwrap(provisionedReferences)
        XCTAssertEqual(references.signing.generation, 1)
        let signingKey = try await keyStore.key(for: references.signing)
        let rotationKey = try await keyStore.key(for: references.rotation)
        XCTAssertEqual(signingKey.count, 32)
        XCTAssertEqual(rotationKey.count, 32)
        try await database.close()

        let controlBytes = try Data(contentsOf: SQLiteLayout.controlDatabase(in: root))
        XCTAssertFalse(String(decoding: controlBytes, as: UTF8.self).contains("correct horse"))
        let columns = try await SQLiteConnection.open(
            storage: .file(path: SQLiteLayout.controlDatabase(in: root).path)
        )
        let columnNames = try await columns.query("PRAGMA table_info(accounts)")
            .compactMap { $0.column("name")?.string }
        XCTAssertFalse(columnNames.contains(where: { $0.contains("private") || $0.contains("envelope") }))
        try await columns.close()
    }

    private func keyReference() throws -> AccountKeyReference {
        try AccountKeyReference(
            accountDID: Self.aliceDID,
            purpose: .signing,
            generation: 1
        )
    }

    private func keyStoreSnapshot(_ root: URL) throws -> [String: Data] {
        let names = try FileManager.default.contentsOfDirectory(atPath: root.path).sorted()
        return try Dictionary(uniqueKeysWithValues: names.map { name in
            let url = root.appending(path: name)
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            let mode = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
            let payload = try Data(contentsOf: url)
            var snapshot = Data("\(mode):\(payload.count):".utf8)
            snapshot.append(payload)
            return (name, snapshot)
        })
    }

    private static let aliceDID = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let bobDID = "did:plc:bcdefghijklmnopqrstuvwxy"

    func testProvisioningSecretsRequireOwnerOnlyFileAndRejectInvalidOrOversizedSources() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = Data(repeating: 0xAB, count: 32)
        let encoded = base64URLEncoded(key)
        let keyFile = root.appending(path: "account-kek")
        try Data((encoded + "\n").utf8).write(to: keyFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyFile.path)

        let config = try AccountProvisioningSecrets.requiredMountedAccountKeyConfiguration(
            activeKeyID: "lab-primary",
            secretFile: keyFile
        )
        XCTAssertEqual(config.activeKeyID, "lab-primary")

        let rawSecret = try AccountProvisioningSecrets.requiredMounted32ByteSecret(secretFile: keyFile)
        XCTAssertEqual(rawSecret, key)

        // Broad permissions are rejected
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: keyFile.path)
        XCTAssertThrowsError(
            try AccountProvisioningSecrets.requiredMountedAccountKeyConfiguration(
                activeKeyID: "lab-primary",
                secretFile: keyFile
            )
        )
        XCTAssertThrowsError(
            try AccountProvisioningSecrets.requiredMounted32ByteSecret(secretFile: keyFile)
        )
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyFile.path)

        // Symlinks are rejected
        let linkFile = root.appending(path: "account-kek-link")
        try FileManager.default.createSymbolicLink(at: linkFile, withDestinationURL: keyFile)
        XCTAssertThrowsError(
            try AccountProvisioningSecrets.requiredMountedAccountKeyConfiguration(
                activeKeyID: "lab-primary",
                secretFile: linkFile
            )
        )

        // Non-canonical or malformed base64url is rejected
        let malformedFile = root.appending(path: "malformed-kek")
        try Data("not-valid-base64url!\n".utf8).write(to: malformedFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: malformedFile.path)
        XCTAssertThrowsError(
            try AccountProvisioningSecrets.requiredMountedAccountKeyConfiguration(
                activeKeyID: "lab-primary",
                secretFile: malformedFile
            )
        )

        // Password file tests
        let passwordFile = root.appending(path: "password")
        try Data("correct horse 🦢\r\n".utf8).write(to: passwordFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: passwordFile.path)
        XCTAssertEqual(try AccountProvisioningSecrets.password(secretFile: passwordFile), "correct horse 🦢")

        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: passwordFile.path)
        XCTAssertThrowsError(try AccountProvisioningSecrets.password(secretFile: passwordFile))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: passwordFile.path)

        let nullPasswordFile = root.appending(path: "null-password")
        try Data([0x61, 0x00, 0x62]).write(to: nullPasswordFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: nullPasswordFile.path)
        XCTAssertThrowsError(try AccountProvisioningSecrets.password(secretFile: nullPasswordFile))
    }

    private func keyConfiguration(activeKeyID: String, byte: UInt8) throws
        -> AccountKeyEncryptionConfiguration
    {
        try AccountKeyEncryptionConfiguration(
            activeKeyID: activeKeyID,
            activeKey: Data(repeating: byte, count: 32)
        )
    }

    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appending(path: "SwanAccountsTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        return url
    }

    private func base64URLEncoded(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func keyFiles(in root: URL) throws -> [URL] {
        try FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "key" }
    }

    private func onlyKeyFile(in root: URL) throws -> URL {
        try keyFiles(in: root).onlyElement()
    }

    private func permissions(of url: URL) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        return try XCTUnwrap(attributes[.posixPermissions] as? NSNumber).intValue
    }

    private func envelopeObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func writeEnvelope(
        _ data: Data,
        replacing fields: [String: Any],
        to url: URL
    ) throws {
        var object = try envelopeObject(data)
        for (field, value) in fields {
            object[field] = value
        }
        try writeEnvelope(object, to: url)
    }

    private func writeEnvelope(_ object: [String: Any], to url: URL) throws {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            .write(to: url)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: url.path
        )
    }

    private func waitUntil(
        _ predicate: @escaping () async -> Bool,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async throws {
        for _ in 0 ..< 100 {
            if await predicate() { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTFail("condition was not reached", file: file, line: line)
    }
}

private struct DirectoryTestHasher: PasswordHasher {
    static let legacyVerifier = "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
    static let currentVerifier = "$argon2id$v=19$m=65536,t=3,p=1$bcdefghijklmnopqrstuvw$BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
    static let acceptedVerifiers: Set<String> = [legacyVerifier, currentVerifier]

    func hash(_ password: String) throws -> String {
        guard !password.isEmpty else { throw SwanError.malformed("empty test password") }
        return Self.currentVerifier
    }

    func verify(_ password: String, encodedHash: String) throws -> Bool {
        password == "correct horse" && Self.acceptedVerifiers.contains(encodedHash)
    }

    func needsRehash(_ encodedHash: String) throws -> Bool {
        encodedHash == Self.legacyVerifier
    }
}

private actor AuthenticationFinalizationBarrier {
    private var entered = false
    private var released = false
    private var entryWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func enter() async {
        entered = true
        let waiters = entryWaiters
        entryWaiters.removeAll()
        for waiter in waiters {
            waiter.resume()
        }
        guard !released else { return }
        await withCheckedContinuation { releaseWaiters.append($0) }
    }

    func waitUntilEntered() async {
        guard !entered else { return }
        await withCheckedContinuation { entryWaiters.append($0) }
    }

    func release() {
        released = true
        let waiters = releaseWaiters
        releaseWaiters.removeAll()
        for waiter in waiters {
            waiter.resume()
        }
    }
}

private struct FinalizationGatedAccountControlStore: AccountControlStore {
    let base: SQLiteControlDatabase
    let barrier: AuthenticationFinalizationBarrier

    func createAccount(_ registration: AccountControlRegistration) async throws -> AccountControlAccount {
        try await base.createAccount(registration)
    }

    func account(did: String) async throws -> AccountControlAccount? {
        try await base.account(did: did)
    }

    func account(canonicalHandle: String) async throws -> AccountControlAccount? {
        try await base.account(canonicalHandle: canonicalHandle)
    }

    func credential(did: String) async throws -> AccountControlCredential? {
        try await base.credential(did: did)
    }

    func replaceCredential(
        did: String,
        expectedVerifier: String,
        replacementVerifier: String,
        now: Date
    ) async throws -> AccountCredentialReplacement {
        try await base.replaceCredential(
            did: did,
            expectedVerifier: expectedVerifier,
            replacementVerifier: replacementVerifier,
            now: now
        )
    }

    func finalizeAuthentication(
        did: String,
        expectedVerifier: String,
        replacementVerifier: String?,
        now: Date
    ) async throws -> AccountAuthenticationFinalization? {
        await barrier.enter()
        return try await base.finalizeAuthentication(
            did: did,
            expectedVerifier: expectedVerifier,
            replacementVerifier: replacementVerifier,
            now: now
        )
    }

    func transitionStatus(
        did: String,
        to status: AccountControlStatus,
        declaration: AccountLifecycleDeclaration,
        emitting: AccountLifecycleEmission?,
        now: Date
    ) async throws -> AccountControlAccount {
        try await base.transitionStatus(
            did: did,
            to: status,
            declaration: declaration,
            emitting: emitting,
            now: now
        )
    }
}

private extension Collection {
    func onlyElement(
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> Element {
        XCTAssertEqual(count, 1, file: file, line: line)
        return try XCTUnwrap(first, file: file, line: line)
    }
}

private func XCTAssertThrowsSwanErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    expected: SwanError,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected \(expected)", file: file, line: line)
    } catch let error as SwanError {
        XCTAssertEqual(error, expected, file: file, line: line)
    } catch {
        XCTFail("unexpected error \(error)", file: file, line: line)
    }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ errorHandler: (any Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("expected error", file: file, line: line)
    } catch {
        errorHandler(error)
    }
}
