import Crypto
import Foundation
import SwanAccounts
import SwanCore
import SwanSQLite
import SwanStorage
import XCTest
@testable import SwanOAuth

/// F14 — the authority signing path must not hand back a key it authorized
/// before an intervening lifecycle or key-generation change.
///
/// `LocalAccountSpaceCredentialSigningKeyResolver` reads the account row and
/// key references, then suspends inside `keyStore.key(for:)`. Its caller signs
/// a two-hour credential the moment it returns. These tests commit a
/// deactivation and a key rotation *inside* that suspension — a deterministic
/// seam, not a sleep — and assert no key is produced.
///
/// The two verification resolvers in the same file already fence exactly this
/// way and have a dedicated fail-closed suite
/// (`LocalCredentialAuthorityFailClosedTests`, including a mid-read lifecycle
/// flip at `:320`). The signing resolver had no behavioural coverage at all.
final class SpaceCredentialSigningFenceTests: XCTestCase {
    private static let authority = "did:plc:abcdefghijklmnopqrstuvwx"

    func testAccountDeactivationDuringKeyStoreReadDoesNotYieldSigningKey() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { try? await fixture.close() }

        let resolver = LocalAccountSpaceCredentialSigningKeyResolver(
            accounts: fixture.accounts,
            keyStore: LifecycleFlippingKeyStore(
                wrapped: fixture.keyStore,
                accounts: fixture.accounts,
                did: Self.authority
            )
        )

        await assertNoSigningKey(
            resolver,
            because: "the resolver must re-read account lifecycle after the key-store suspension"
        )
    }

    func testKeyRotationDuringKeyStoreReadDoesNotYieldSigningKey() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { try? await fixture.close() }

        let resolver = LocalAccountSpaceCredentialSigningKeyResolver(
            accounts: fixture.accounts,
            keyStore: RotatingKeyStore(
                wrapped: fixture.keyStore,
                control: fixture.control,
                did: Self.authority
            )
        )

        await assertNoSigningKey(
            resolver,
            because: "the resolver must re-read the key generation after the key-store suspension"
        )
    }

    /// Regression guard: an unraced resolution still returns the authority key,
    /// so the fence cannot pass by refusing everything.
    func testUnracedResolutionStillReturnsTheAuthoritySigningKey() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { try? await fixture.close() }

        let resolver = LocalAccountSpaceCredentialSigningKeyResolver(
            accounts: fixture.accounts,
            keyStore: fixture.keyStore
        )
        let resolved = try await resolver.signingKey(for: Self.authority)
        XCTAssertEqual(resolved?.authority, Self.authority)
        XCTAssertEqual(resolved?.keyID, PermissionedDataJWT.spaceCredentialKeyID)
    }

    /// An unmanaged DID stays a fall-through (`nil`), not the terminal error the
    /// fence raises. Collapsing the two would let composition treat "changed
    /// underneath us" as "not mine" and try another authority.
    func testUnmanagedAuthorityStillFallsThroughAsNil() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { try? await fixture.close() }

        let resolver = LocalAccountSpaceCredentialSigningKeyResolver(
            accounts: fixture.accounts,
            keyStore: fixture.keyStore
        )
        let resolved = try await resolver.signingKey(
            for: "did:plc:zyxwvutsrqponmlkjihgfedc"
        )
        XCTAssertNil(resolved)
    }

    // MARK: Helpers

    private func assertNoSigningKey(
        _ resolver: LocalAccountSpaceCredentialSigningKeyResolver,
        because message: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            let resolved = try await resolver.signingKey(for: Self.authority)
            XCTAssertNil(resolved, message, file: file, line: line)
        } catch let error as SwanError {
            guard case .unavailable = error else {
                return XCTFail(
                    "expected an opaque availability failure, got \(error)",
                    file: file,
                    line: line
                )
            }
        } catch {
            XCTFail("expected SwanError.unavailable, got \(error)", file: file, line: line)
        }
    }

    /// Deactivates the authority account inside the key-store suspension.
    private actor LifecycleFlippingKeyStore: AccountKeyStore {
        private let wrapped: any AccountKeyStore
        private let accounts: DurableAccountDirectory
        private let did: String
        private var flipped = false

        init(wrapped: any AccountKeyStore, accounts: DurableAccountDirectory, did: String) {
            self.wrapped = wrapped
            self.accounts = accounts
            self.did = did
        }

        func key(for reference: AccountKeyReference) async throws -> Data {
            let material = try await wrapped.key(for: reference)
            if !flipped {
                flipped = true
                _ = try await accounts.transitionStatus(
                    did: did,
                    to: .deactivated,
                    now: Date()
                )
            }
            return material
        }

        func create(_ key: Data, for reference: AccountKeyReference) async throws {
            try await wrapped.create(key, for: reference)
        }

        func createBatch(_ materials: [AccountKeyMaterial]) async throws {
            try await wrapped.createBatch(materials)
        }
    }

    /// Rotates the authority signing key inside the key-store suspension, so
    /// the scalar already read belongs to a superseded generation.
    private actor RotatingKeyStore: AccountKeyStore {
        private let wrapped: any AccountKeyStore
        private let control: SQLiteControlDatabase
        private let did: String
        private var rotated = false

        init(wrapped: any AccountKeyStore, control: SQLiteControlDatabase, did: String) {
            self.wrapped = wrapped
            self.control = control
            self.did = did
        }

        func key(for reference: AccountKeyReference) async throws -> Data {
            let material = try await wrapped.key(for: reference)
            if !rotated {
                rotated = true
                let next = reference.generation + 1
                _ = try await AccountKeyProvisioner(keyStore: wrapped)
                    .provisionRotation(accountDID: did, generation: next)
                _ = try await control.rotateAccountKeys(
                    did: did,
                    request: try AccountControlKeyRotationRequest(
                        expectedGeneration: reference.generation,
                        signingKey: try .init(purpose: .signing, generation: next),
                        rotationKey: try .init(purpose: .rotation, generation: next)
                    ),
                    now: Date()
                )
            }
            return material
        }

        func create(_ key: Data, for reference: AccountKeyReference) async throws {
            try await wrapped.create(key, for: reference)
        }

        func createBatch(_ materials: [AccountKeyMaterial]) async throws {
            try await wrapped.createBatch(materials)
        }
    }

    private struct Fixture: Sendable {
        let root: URL
        let control: SQLiteControlDatabase
        let keyStore: FileAccountKeyStore
        let accounts: DurableAccountDirectory

        static func make() async throws -> Fixture {
            let root = FileManager.default.temporaryDirectory
                .appending(path: "SpaceCredentialSigningFenceTests-\(UUID().uuidString)")
            try FileManager.default.createDirectory(
                at: root,
                withIntermediateDirectories: true
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: NSNumber(value: 0o700)],
                ofItemAtPath: root.path
            )
            let control = try await SQLiteControlDatabase(dataDirectory: root)
            do {
                let keyStore = try FileAccountKeyStore(
                    root: root.appending(path: "keys"),
                    configuration: try .init(
                        activeKeyID: "fence-kek",
                        activeKey: Data(repeating: 0x3A, count: 32)
                    )
                )
                let keys = try await AccountKeyProvisioner(keyStore: keyStore)
                    .provisionInitial(
                        accountDID: SpaceCredentialSigningFenceTests.authority
                    )
                _ = try await control.createAccount(
                    try AccountControlRegistration(
                        did: SpaceCredentialSigningFenceTests.authority,
                        canonicalHandle: "authority.example.com",
                        passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                        signingKey: try .init(
                            purpose: .signing,
                            generation: keys.signingReference.generation
                        ),
                        rotationKey: try .init(
                            purpose: .rotation,
                            generation: keys.rotationReference.generation
                        ),
                        createdAt: Date(timeIntervalSince1970: 1_750_000_000)
                    )
                )
                let hasher = try LibsodiumArgon2idHasher(policy: .interactive)
                return Fixture(
                    root: root,
                    control: control,
                    keyStore: keyStore,
                    accounts: DurableAccountDirectory(
                        store: control,
                        passwordHasher: hasher,
                        verificationExecutor: try Argon2idVerificationExecutor(
                            hasher: hasher,
                            maximumConcurrentVerifications: 1,
                            maximumQueuedVerifications: 1
                        )
                    )
                )
            } catch {
                try? await control.close()
                try? FileManager.default.removeItem(at: root)
                throw error
            }
        }

        func close() async throws {
            try await control.close()
            try? FileManager.default.removeItem(at: root)
        }
    }
}
