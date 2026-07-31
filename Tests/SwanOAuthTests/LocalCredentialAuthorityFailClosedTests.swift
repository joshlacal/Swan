import Crypto
import Foundation
import SwanAccounts
import SwanCore
import SwanSQLite
import SwanStorage
import SwanSpaces
import XCTest
@testable import SwanOAuth

final class LocalCredentialAuthorityFailClosedTests: XCTestCase {
    private let managedDID = "did:plc:abcdefghijklmnopqrstuvwx"
    private let unknownDID = "did:plc:bcdefghijklmnopqrstuvwxy"
    private let createdAt = Date(timeIntervalSince1970: 1_750_000_000)

    func testActiveManagedIssuerWithUnsupportedKeyIDDoesNotReachFallbacks() async throws {
        try await withManagedIssuerFixture { fixture in
            let localKeys = GenerationPublicKeyStore(keys: [
                1: fixture.initialKey.publicKey.x963Representation,
            ])
            let pin = ResolverProbe(key: .p256(P256.Signing.PrivateKey().publicKey))
            let remote = ResolverProbe(key: .p256(P256.Signing.PrivateKey().publicKey))
            let resolver = CompositeSpaceCredentialPublicKeyResolver(
                local: LocalAccountSpaceCredentialPublicKeyResolver(
                    accounts: fixture.accounts,
                    publicKeyStore: localKeys
                ),
                remote: remote,
                prevalidatedPinned: pin
            )

            await assertManagedAuthorityUnavailable {
                _ = try await resolver.publicKey(
                    for: fixture.did,
                    keyID: "#retired-space-key"
                )
            }
            let pinCalls = await pin.callCount()
            let remoteCalls = await remote.callCount()
            let keyReads = await localKeys.readCount()
            XCTAssertEqual(pinCalls, 0)
            XCTAssertEqual(remoteCalls, 0)
            XCTAssertEqual(keyReads, 0)
        }
    }

    func testDeactivatedManagedIssuerDoesNotReachFallbacks() async throws {
        try await withManagedIssuerFixture { fixture in
            _ = try await fixture.accounts.transitionStatus(
                did: fixture.did,
                to: .deactivated,
                now: createdAt.addingTimeInterval(1)
            )
            try await assertManagedIssuerDoesNotReachFallbacks(fixture)
        }
    }

    func testDeletedManagedIssuerDoesNotReachFallbacks() async throws {
        try await withManagedIssuerFixture { fixture in
            _ = try await fixture.control.beginDeletion(
                did: fixture.did,
                declaration: AccountLifecycleDeclaration(
                    tombstone: try AccountTombstoneMetadata(
                        declaredAt: createdAt.addingTimeInterval(1),
                        reason: "resolver-test"
                    )
                ),
                now: createdAt.addingTimeInterval(1)
            )
            try await assertManagedIssuerDoesNotReachFallbacks(fixture)
        }
    }

    func testDeactivatedManagedDelegationIssuerDoesNotReachFallbacks() async throws {
        try await withManagedIssuerFixture { fixture in
            _ = try await fixture.accounts.transitionStatus(
                did: fixture.did,
                to: .deactivated,
                now: createdAt.addingTimeInterval(1)
            )
            try await assertManagedDelegationIssuerDoesNotReachFallbacks(fixture)
        }
    }

    func testDeletedManagedDelegationIssuerDoesNotReachFallbacks() async throws {
        try await withManagedIssuerFixture { fixture in
            _ = try await fixture.control.beginDeletion(
                did: fixture.did,
                declaration: AccountLifecycleDeclaration(
                    tombstone: try AccountTombstoneMetadata(
                        declaredAt: createdAt.addingTimeInterval(1),
                        reason: "delegation-resolver-test"
                    )
                ),
                now: createdAt.addingTimeInterval(1)
            )
            try await assertManagedDelegationIssuerDoesNotReachFallbacks(fixture)
        }
    }

    func testManagedDelegationIssuerWithUnsupportedKeyIDDoesNotReachFallbacks() async throws {
        try await withManagedIssuerFixture { fixture in
            let localKeys = GenerationPublicKeyStore(keys: [
                1: fixture.initialKey.publicKey.x963Representation,
            ])
            let remote = DelegationResolverProbe(key: .p256(fixture.initialKey.publicKey))
            let resolver = try await CompositeSpaceDelegationPublicKeyResolver(
                local: LocalAccountSpaceDelegationPublicKeyResolver(
                    accounts: fixture.accounts,
                    publicKeyStore: localKeys
                ),
                remote: remote,
                pinned: []
            )

            await assertManagedDelegationUnavailable {
                _ = try await resolver.publicKey(
                    for: fixture.did,
                    keyID: "#retired-delegation-key"
                )
            }
            let remoteCalls = await remote.callCount()
            let keyReads = await localKeys.readCount()
            XCTAssertEqual(remoteCalls, 0)
            XCTAssertEqual(keyReads, 0)
        }
    }

    func testManagedDelegationIssuerWithMissingPublicKeyDoesNotReachFallbacks() async throws {
        try await withManagedIssuerFixture { fixture in
            let localKeys = GenerationPublicKeyStore(keys: [:])
            let remote = DelegationResolverProbe(key: .p256(fixture.initialKey.publicKey))
            let resolver = try await CompositeSpaceDelegationPublicKeyResolver(
                local: LocalAccountSpaceDelegationPublicKeyResolver(
                    accounts: fixture.accounts,
                    publicKeyStore: localKeys
                ),
                remote: remote,
                pinned: []
            )

            await assertManagedDelegationUnavailable {
                _ = try await resolver.publicKey(
                    for: fixture.did,
                    keyID: PermissionedDataJWT.delegationKeyID
                )
            }
            let remoteCalls = await remote.callCount()
            let keyReads = await localKeys.readCount()
            XCTAssertEqual(remoteCalls, 0)
            XCTAssertEqual(keyReads, 1)
        }
    }

    func testManagedDelegationIssuerWithCorruptPublicKeyDoesNotReachFallbacks() async throws {
        try await withManagedIssuerFixture { fixture in
            let localKeys = GenerationPublicKeyStore(keys: [1: Data([0x04, 0x01])])
            let remote = DelegationResolverProbe(key: .p256(fixture.initialKey.publicKey))
            let resolver = try await CompositeSpaceDelegationPublicKeyResolver(
                local: LocalAccountSpaceDelegationPublicKeyResolver(
                    accounts: fixture.accounts,
                    publicKeyStore: localKeys
                ),
                remote: remote,
                pinned: []
            )

            await assertManagedDelegationUnavailable {
                _ = try await resolver.publicKey(
                    for: fixture.did,
                    keyID: PermissionedDataJWT.delegationKeyID
                )
            }
            let remoteCalls = await remote.callCount()
            let keyReads = await localKeys.readCount()
            XCTAssertEqual(remoteCalls, 0)
            XCTAssertEqual(keyReads, 1)
        }
    }

    func testDelegationLifecycleChangeDuringKeyReadDoesNotReachFallbacks() async throws {
        try await withManagedIssuerFixture { fixture in
            let localKeys = LifecycleFlippingPublicKeyStore(
                accounts: fixture.accounts,
                did: fixture.did,
                key: fixture.initialKey.publicKey.x963Representation,
                transitionAt: createdAt.addingTimeInterval(2)
            )
            let remote = DelegationResolverProbe(key: .p256(fixture.initialKey.publicKey))
            let resolver = try await CompositeSpaceDelegationPublicKeyResolver(
                local: LocalAccountSpaceDelegationPublicKeyResolver(
                    accounts: fixture.accounts,
                    publicKeyStore: localKeys
                ),
                remote: remote,
                pinned: []
            )

            await assertManagedDelegationUnavailable {
                _ = try await resolver.publicKey(
                    for: fixture.did,
                    keyID: PermissionedDataJWT.delegationKeyID
                )
            }
            let remoteCalls = await remote.callCount()
            XCTAssertEqual(remoteCalls, 0)
        }
    }

    func testUnknownDelegationIssuerFallsThroughToConfiguredRemoteResolver() async throws {
        try await withManagedIssuerFixture { fixture in
            let expected = P256.Signing.PrivateKey()
            let remote = DelegationResolverProbe(key: .p256(expected.publicKey))
            let resolver = try await CompositeSpaceDelegationPublicKeyResolver(
                local: LocalAccountSpaceDelegationPublicKeyResolver(
                    accounts: fixture.accounts,
                    publicKeyStore: GenerationPublicKeyStore(keys: [
                        1: fixture.initialKey.publicKey.x963Representation,
                    ])
                ),
                remote: remote,
                pinned: []
            )

            let resolved = try await resolver.publicKey(
                for: unknownDID,
                keyID: PermissionedDataJWT.delegationKeyID
            )
            XCTAssertEqual(
                resolved?.deterministicIdentity,
                PermissionedDataJWTVerificationKey.p256(expected.publicKey)
                    .deterministicIdentity
            )
            let remoteCalls = await remote.callCount()
            XCTAssertEqual(remoteCalls, 1)
        }
    }

    func testStartupDelegationPinPreflightRejectsDeactivatedManagedIssuer() async throws {
        try await withManagedIssuerFixture { fixture in
            _ = try await fixture.accounts.transitionStatus(
                did: fixture.did,
                to: .deactivated,
                now: createdAt.addingTimeInterval(1)
            )
            await assertManagedDelegationUnavailable {
                _ = try await CompositeSpaceDelegationPublicKeyResolver(
                    local: LocalAccountSpaceDelegationPublicKeyResolver(
                        accounts: fixture.accounts,
                        publicKeyStore: GenerationPublicKeyStore(keys: [
                            1: fixture.initialKey.publicKey.x963Representation,
                        ])
                    ),
                    pinned: [
                        try .init(
                            issuer: fixture.did,
                            generation: 1,
                            publicKey: fixture.initialKey.publicKey
                        ),
                    ]
                )
            }
        }
    }

    func testManagedIssuerWithMissingPublicKeyDoesNotReachFallbacks() async throws {
        try await withManagedIssuerFixture { fixture in
            let localKeys = GenerationPublicKeyStore(keys: [:])
            let pin = ResolverProbe(key: .p256(fixture.initialKey.publicKey))
            let remote = ResolverProbe(key: .p256(fixture.initialKey.publicKey))
            let resolver = CompositeSpaceCredentialPublicKeyResolver(
                local: LocalAccountSpaceCredentialPublicKeyResolver(
                    accounts: fixture.accounts,
                    publicKeyStore: localKeys
                ),
                remote: remote,
                prevalidatedPinned: pin
            )

            await assertManagedAuthorityUnavailable {
                _ = try await resolver.publicKey(
                    for: fixture.did,
                    keyID: PermissionedDataJWT.spaceCredentialKeyID
                )
            }
            let pinCalls = await pin.callCount()
            let remoteCalls = await remote.callCount()
            XCTAssertEqual(pinCalls, 0)
            XCTAssertEqual(remoteCalls, 0)
        }
    }

    func testManagedIssuerWithCorruptPublicKeyDoesNotReachFallbacks() async throws {
        try await withManagedIssuerFixture { fixture in
            let localKeys = GenerationPublicKeyStore(keys: [1: Data([0x04, 0x01])])
            let pin = ResolverProbe(key: .p256(fixture.initialKey.publicKey))
            let remote = ResolverProbe(key: .p256(fixture.initialKey.publicKey))
            let resolver = CompositeSpaceCredentialPublicKeyResolver(
                local: LocalAccountSpaceCredentialPublicKeyResolver(
                    accounts: fixture.accounts,
                    publicKeyStore: localKeys
                ),
                remote: remote,
                prevalidatedPinned: pin
            )

            await assertManagedAuthorityUnavailable {
                _ = try await resolver.publicKey(
                    for: fixture.did,
                    keyID: PermissionedDataJWT.spaceCredentialKeyID
                )
            }
            let pinCalls = await pin.callCount()
            let remoteCalls = await remote.callCount()
            XCTAssertEqual(pinCalls, 0)
            XCTAssertEqual(remoteCalls, 0)
        }
    }

    func testLifecycleChangeDuringKeyReadDoesNotReachFallbacks() async throws {
        try await withManagedIssuerFixture { fixture in
            let localKeys = LifecycleFlippingPublicKeyStore(
                accounts: fixture.accounts,
                did: fixture.did,
                key: fixture.initialKey.publicKey.x963Representation,
                transitionAt: createdAt.addingTimeInterval(2)
            )
            let pin = ResolverProbe(key: .p256(fixture.initialKey.publicKey))
            let remote = ResolverProbe(key: .p256(fixture.initialKey.publicKey))
            let resolver = CompositeSpaceCredentialPublicKeyResolver(
                local: LocalAccountSpaceCredentialPublicKeyResolver(
                    accounts: fixture.accounts,
                    publicKeyStore: localKeys
                ),
                remote: remote,
                prevalidatedPinned: pin
            )

            await assertManagedAuthorityUnavailable {
                _ = try await resolver.publicKey(
                    for: fixture.did,
                    keyID: PermissionedDataJWT.spaceCredentialKeyID
                )
            }
            let pinCalls = await pin.callCount()
            let remoteCalls = await remote.callCount()
            XCTAssertEqual(pinCalls, 0)
            XCTAssertEqual(remoteCalls, 0)
        }
    }

    func testUnknownIssuerFallsThroughToConfiguredFallbackChain() async throws {
        try await withManagedIssuerFixture { fixture in
            let expected = P256.Signing.PrivateKey()
            let pin = ResolverProbe(key: nil)
            let remote = ResolverProbe(key: .p256(expected.publicKey))
            let resolver = CompositeSpaceCredentialPublicKeyResolver(
                local: LocalAccountSpaceCredentialPublicKeyResolver(
                    accounts: fixture.accounts,
                    publicKeyStore: GenerationPublicKeyStore(keys: [
                        1: fixture.initialKey.publicKey.x963Representation,
                    ])
                ),
                remote: remote,
                prevalidatedPinned: pin
            )

            let resolvedResult = try await resolver.publicKey(
                for: unknownDID,
                keyID: PermissionedDataJWT.spaceCredentialKeyID
            )
            let resolved = try XCTUnwrap(resolvedResult)
            XCTAssertEqual(
                resolved.deterministicIdentity,
                PermissionedDataJWTVerificationKey.p256(expected.publicKey)
                    .deterministicIdentity
            )
            let pinCalls = await pin.callCount()
            let remoteCalls = await remote.callCount()
            XCTAssertEqual(pinCalls, 1)
            XCTAssertEqual(remoteCalls, 1)
        }
    }

    func testReactivatedIssuerResolvesOnlyCurrentRotatedKey() async throws {
        try await withManagedIssuerFixture { fixture in
            let rotatedKey = P256.Signing.PrivateKey()
            let localKeys = GenerationPublicKeyStore(keys: [
                1: fixture.initialKey.publicKey.x963Representation,
                2: rotatedKey.publicKey.x963Representation,
            ])
            _ = try await fixture.control.rotateAccountKeys(
                did: fixture.did,
                request: try AccountControlKeyRotationRequest(
                    expectedGeneration: 1,
                    signingKey: try .init(purpose: .signing, generation: 2),
                    rotationKey: try .init(purpose: .rotation, generation: 2)
                ),
                now: createdAt.addingTimeInterval(1)
            )
            _ = try await fixture.accounts.transitionStatus(
                did: fixture.did,
                to: .deactivated,
                now: createdAt.addingTimeInterval(2)
            )
            _ = try await fixture.accounts.transitionStatus(
                did: fixture.did,
                to: .active,
                now: createdAt.addingTimeInterval(3)
            )
            // A configured pin is a consistency assertion even when the
            // managed local source resolves successfully. Use the current
            // rotated key here; the startup conflict tests separately prove
            // that a stale generation-one pin is rejected.
            let pin = ResolverProbe(key: .p256(rotatedKey.publicKey))
            let remote = ResolverProbe(key: .p256(fixture.initialKey.publicKey))
            let resolver = CompositeSpaceCredentialPublicKeyResolver(
                local: LocalAccountSpaceCredentialPublicKeyResolver(
                    accounts: fixture.accounts,
                    publicKeyStore: localKeys
                ),
                remote: remote,
                prevalidatedPinned: pin
            )

            let resolvedResult = try await resolver.publicKey(
                for: fixture.did,
                keyID: PermissionedDataJWT.spaceCredentialKeyID
            )
            let resolved = try XCTUnwrap(resolvedResult)
            XCTAssertEqual(
                resolved.deterministicIdentity,
                PermissionedDataJWTVerificationKey.p256(rotatedKey.publicKey)
                    .deterministicIdentity
            )
            XCTAssertNotEqual(
                resolved.deterministicIdentity,
                PermissionedDataJWTVerificationKey.p256(fixture.initialKey.publicKey)
                    .deterministicIdentity
            )
            let pinCalls = await pin.callCount()
            let remoteCalls = await remote.callCount()
            XCTAssertEqual(pinCalls, 1)
            XCTAssertEqual(remoteCalls, 0)
        }
    }

    func testStartupPinPreflightRejectsDeactivatedManagedIssuer() async throws {
        try await withManagedIssuerFixture { fixture in
            _ = try await fixture.accounts.transitionStatus(
                did: fixture.did,
                to: .deactivated,
                now: createdAt.addingTimeInterval(1)
            )
            await assertManagedAuthorityUnavailable {
                _ = try await CompositeSpaceCredentialPublicKeyResolver(
                    local: LocalAccountSpaceCredentialPublicKeyResolver(
                        accounts: fixture.accounts,
                        publicKeyStore: GenerationPublicKeyStore(keys: [
                            1: fixture.initialKey.publicKey.x963Representation,
                        ])
                    ),
                    pinned: [
                        try .init(
                            authority: fixture.did,
                            generation: 1,
                            publicKey: fixture.initialKey.publicKey
                        ),
                    ]
                )
            }
        }
    }

    func testStartupPinPreflightRejectsDeletedManagedIssuer() async throws {
        try await withManagedIssuerFixture { fixture in
            _ = try await fixture.control.beginDeletion(
                did: fixture.did,
                declaration: AccountLifecycleDeclaration(
                    tombstone: try AccountTombstoneMetadata(
                        declaredAt: createdAt.addingTimeInterval(1),
                        reason: "resolver-test"
                    )
                ),
                now: createdAt.addingTimeInterval(1)
            )
            await assertManagedAuthorityUnavailable {
                _ = try await CompositeSpaceCredentialPublicKeyResolver(
                    local: LocalAccountSpaceCredentialPublicKeyResolver(
                        accounts: fixture.accounts,
                        publicKeyStore: GenerationPublicKeyStore(keys: [
                            1: fixture.initialKey.publicKey.x963Representation,
                        ])
                    ),
                    pinned: [
                        try .init(
                            authority: fixture.did,
                            generation: 1,
                            publicKey: fixture.initialKey.publicKey
                        ),
                    ]
                )
            }
        }
    }

    func testStartupPinPreflightRejectsConflictingActiveManagedIssuerKey() async throws {
        try await withManagedIssuerFixture { fixture in
            let conflicting = P256.Signing.PrivateKey()
            await assertAnyError {
                _ = try await CompositeSpaceCredentialPublicKeyResolver(
                    local: LocalAccountSpaceCredentialPublicKeyResolver(
                        accounts: fixture.accounts,
                        publicKeyStore: GenerationPublicKeyStore(keys: [
                            1: fixture.initialKey.publicKey.x963Representation,
                        ])
                    ),
                    pinned: [
                        try .init(
                            authority: fixture.did,
                            generation: 1,
                            publicKey: conflicting.publicKey
                        ),
                    ]
                )
            }
        }
    }

    func testCredentialVerifierMapsManagedAuthorityFailureToOpaqueUnavailable() async throws {
        try await withManagedIssuerFixture { fixture in
            _ = try await fixture.accounts.transitionStatus(
                did: fixture.did,
                to: .deactivated,
                now: createdAt.addingTimeInterval(1)
            )
            let resolver = LocalAccountSpaceCredentialPublicKeyResolver(
                accounts: fixture.accounts,
                publicKeyStore: GenerationPublicKeyStore(keys: [
                    1: fixture.initialKey.publicKey.x963Representation,
                ])
            )
            let space = try SpaceURI(
                authority: fixture.did,
                spaceType: "app.bsky.bookmarks",
                skey: "fail-closed"
            )
            let token = try PermissionedDataJWT.createSpaceCredential(
                issuer: fixture.did,
                space: space,
                key: fixture.initialKey,
                now: createdAt
            )

            await assertOpaqueUnavailable {
                _ = try await DurableSpaceCredentialVerifier(publicKeys: resolver)
                    .authorization(
                        for: token,
                        expectedSpace: space,
                        now: createdAt.addingTimeInterval(1)
                    )
            }
        }
    }

    private func assertManagedIssuerDoesNotReachFallbacks(
        _ fixture: ManagedIssuerFixture
    ) async throws {
        let localKeys = GenerationPublicKeyStore(keys: [
            1: fixture.initialKey.publicKey.x963Representation,
        ])
        let pin = ResolverProbe(key: .p256(fixture.initialKey.publicKey))
        let remote = ResolverProbe(key: .p256(fixture.initialKey.publicKey))
        let resolver = CompositeSpaceCredentialPublicKeyResolver(
            local: LocalAccountSpaceCredentialPublicKeyResolver(
                accounts: fixture.accounts,
                publicKeyStore: localKeys
            ),
            remote: remote,
            prevalidatedPinned: pin
        )

        await assertManagedAuthorityUnavailable {
            _ = try await resolver.publicKey(
                for: fixture.did,
                keyID: PermissionedDataJWT.spaceCredentialKeyID
            )
        }
        let pinCalls = await pin.callCount()
        let remoteCalls = await remote.callCount()
        let keyReads = await localKeys.readCount()
        XCTAssertEqual(pinCalls, 0)
        XCTAssertEqual(remoteCalls, 0)
        XCTAssertEqual(keyReads, 0)
    }

    private func assertManagedDelegationIssuerDoesNotReachFallbacks(
        _ fixture: ManagedIssuerFixture
    ) async throws {
        let localKeys = GenerationPublicKeyStore(keys: [
            1: fixture.initialKey.publicKey.x963Representation,
        ])
        let remote = DelegationResolverProbe(key: .p256(fixture.initialKey.publicKey))
        let resolver = try await CompositeSpaceDelegationPublicKeyResolver(
            local: LocalAccountSpaceDelegationPublicKeyResolver(
                accounts: fixture.accounts,
                publicKeyStore: localKeys
            ),
            remote: remote,
            pinned: []
        )

        await assertManagedDelegationUnavailable {
            _ = try await resolver.publicKey(
                for: fixture.did,
                keyID: PermissionedDataJWT.delegationKeyID
            )
        }
        let remoteCalls = await remote.callCount()
        let keyReads = await localKeys.readCount()
        XCTAssertEqual(remoteCalls, 0)
        XCTAssertEqual(keyReads, 0)
    }

    private func withManagedIssuerFixture<T>(
        _ body: (ManagedIssuerFixture) async throws -> T
    ) async throws -> T {
        let fixture = try await ManagedIssuerFixture(
            did: managedDID,
            createdAt: createdAt
        )
        do {
            let result = try await body(fixture)
            try await fixture.close()
            return result
        } catch {
            try? await fixture.close()
            throw error
        }
    }
}

private struct ManagedIssuerFixture: Sendable {
    let root: URL
    let control: SQLiteControlDatabase
    let accounts: DurableAccountDirectory
    let did: String
    let initialKey: P256.Signing.PrivateKey

    init(did: String, createdAt: Date) async throws {
        self.did = did
        root = FileManager.default.temporaryDirectory
            .appending(path: "LocalCredentialAuthorityFailClosedTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o700)],
            ofItemAtPath: root.path
        )
        control = try await SQLiteControlDatabase(dataDirectory: root)
        initialKey = P256.Signing.PrivateKey()
        _ = try await control.createAccount(
            try AccountControlRegistration(
                did: did,
                canonicalHandle: "managed-authority.example.com",
                passwordVerifier: "$argon2id$v=19$m=65536,t=2,p=1$abcdefghijklmnopqrstuv$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
                signingKey: try .init(purpose: .signing, generation: 1),
                rotationKey: try .init(purpose: .rotation, generation: 1),
                createdAt: createdAt
            )
        )
        let hasher = try LibsodiumArgon2idHasher(policy: .interactive)
        accounts = DurableAccountDirectory(
            store: control,
            passwordHasher: hasher,
            verificationExecutor: try Argon2idVerificationExecutor(
                hasher: hasher,
                maximumConcurrentVerifications: 1,
                maximumQueuedVerifications: 1
            )
        )
    }

    func close() async throws {
        try await control.close()
        try FileManager.default.removeItem(at: root)
    }
}

private actor GenerationPublicKeyStore: AccountKeyPublicKeyStore {
    private let keys: [UInt64: Data]
    private var reads = 0

    init(keys: [UInt64: Data]) {
        self.keys = keys
    }

    func publicKey(for reference: AccountKeyReference) -> Data? {
        reads += 1
        return keys[reference.generation]
    }

    func readCount() -> Int {
        reads
    }
}

private actor LifecycleFlippingPublicKeyStore: AccountKeyPublicKeyStore {
    private let accounts: DurableAccountDirectory
    private let did: String
    private let key: Data
    private let transitionAt: Date
    private var didFlip = false

    init(
        accounts: DurableAccountDirectory,
        did: String,
        key: Data,
        transitionAt: Date
    ) {
        self.accounts = accounts
        self.did = did
        self.key = key
        self.transitionAt = transitionAt
    }

    func publicKey(for _: AccountKeyReference) async throws -> Data? {
        if !didFlip {
            didFlip = true
            _ = try await accounts.transitionStatus(
                did: did,
                to: .deactivated,
                now: transitionAt
            )
        }
        return key
    }
}

private actor ResolverProbe: SpaceCredentialPublicKeyResolver {
    private let key: PermissionedDataJWTVerificationKey?
    private var calls = 0

    init(key: PermissionedDataJWTVerificationKey?) {
        self.key = key
    }

    func publicKey(
        for _: String,
        keyID _: String
    ) -> PermissionedDataJWTVerificationKey? {
        calls += 1
        return key
    }

    func callCount() -> Int {
        calls
    }
}

private actor DelegationResolverProbe: SpaceDelegationPublicKeyResolver {
    private let key: PermissionedDataJWTVerificationKey?
    private var calls = 0

    init(key: PermissionedDataJWTVerificationKey?) {
        self.key = key
    }

    func publicKey(
        for _: String,
        keyID _: String
    ) -> PermissionedDataJWTVerificationKey? {
        calls += 1
        return key
    }

    func callCount() -> Int {
        calls
    }
}

private func assertManagedAuthorityUnavailable<T>(
    _ expression: () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected managed authority resolution to fail closed", file: file, line: line)
    } catch let error as SpaceCredentialPublicKeyResolutionError {
        XCTAssertEqual(error, .unavailable, file: file, line: line)
    } catch {
        XCTFail(
            "expected opaque credential-key resolution error, got \(error)",
            file: file,
            line: line
        )
    }
}

private func assertManagedDelegationUnavailable<T>(
    _ expression: () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected managed delegation resolution to fail closed", file: file, line: line)
    } catch let error as SpaceDelegationPublicKeyResolutionError {
        XCTAssertEqual(error, .unavailable, file: file, line: line)
    } catch {
        XCTFail(
            "expected opaque delegation-key resolution error, got \(error)",
            file: file,
            line: line
        )
    }
}

private func assertAnyError<T>(
    _ expression: () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected operation to throw", file: file, line: line)
    } catch {}
}

private func assertOpaqueUnavailable<T>(
    _ expression: () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected unavailable verification key", file: file, line: line)
    } catch let error as SwanError {
        guard case .unavailable = error else {
            XCTFail("expected SwanError.unavailable, got \(error)", file: file, line: line)
            return
        }
    } catch {
        XCTFail("expected opaque SwanError.unavailable, got \(error)", file: file, line: line)
    }
}
