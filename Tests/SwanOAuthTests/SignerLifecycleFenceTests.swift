import Crypto
import Foundation
import SwanAccounts
import SwanCore
import SwanSpaces
import SwanSQLite
import SwanStorage
import XCTest
@testable import SwanOAuth

/// F15/F32/F44/F45 (signing fences) and F16 (service-key resolution).
///
/// Every local signer reads account lifecycle and key references, then suspends
/// inside `keyStore.key(for:)`, then signs. Nothing re-checked the account after
/// that suspension, so a deactivation or key rotation committed while the
/// key-store read was in flight still produced a signed artefact. Two of the
/// four carried a comment stating "Do not perform an await after this point"
/// immediately above an await.
///
/// These tests commit the lifecycle change *inside* the suspension — a
/// deterministic seam, not a sleep — and assert no artefact is produced. The
/// sibling suite `SpaceCredentialSigningFenceTests` fences the space-credential
/// signing resolver the same way; the fence itself is now one shared method on
/// `DurableAccountDirectory` rather than four hand-copied bodies.
///
/// F16 is the read side of the same lifecycle question:
/// `LocalAccountSpaceServicePublicKeyResolver` returned `nil` for a deactivated
/// managed account, and `CompositeSpaceServicePublicKeyResolver` reads `nil` as
/// permission to fall through to an operator pin.
final class SignerLifecycleFenceTests: XCTestCase {
    private static let accountDID = "did:plc:abcdefghijklmnopqrstuvwx"
    private static let peerDID = "did:plc:zyxwvutsrqponmlkjihgfedc"
    private static let unmanagedDID = "did:plc:bcdefghijklmnopqrstuvwxy"

    // MARK: F32 — service authentication issuer

    func testServiceAuthenticationIssuerRefusesAfterDeactivationDuringKeyRead() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { try? await fixture.close() }

        let issuer = LocalAccountSpaceServiceAuthenticationIssuer(
            accounts: fixture.accounts,
            keyStore: fixture.deactivatingKeyStore()
        )
        await assertUnavailable(
            "service authentication issuer signed across a deactivation"
        ) {
            try await issuer.issue(
                issuer: Self.accountDID,
                audience: Self.peerDID,
                method: "com.atproto.space.notifyWrite",
                eventID: "fence-event",
                now: Date(timeIntervalSince1970: 1_750_000_000)
            )
        }
    }

    func testServiceAuthenticationIssuerRefusesAfterKeyRotationDuringKeyRead() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { try? await fixture.close() }

        let issuer = LocalAccountSpaceServiceAuthenticationIssuer(
            accounts: fixture.accounts,
            keyStore: fixture.rotatingKeyStore()
        )
        await assertUnavailable(
            "service authentication issuer signed with a superseded generation"
        ) {
            try await issuer.issue(
                issuer: Self.accountDID,
                audience: Self.peerDID,
                method: "com.atproto.space.notifyWrite",
                eventID: "fence-event",
                now: Date(timeIntervalSince1970: 1_750_000_000)
            )
        }
    }

    // MARK: F15 — proxy service token issuer (highest-QPS route)

    func testProxyServiceTokenIssuerRefusesAfterDeactivationDuringKeyRead() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { try? await fixture.close() }

        let issuer = LocalAccountProxyServiceTokenIssuer(
            accounts: fixture.accounts,
            keyStore: fixture.deactivatingKeyStore()
        )
        await assertUnavailable("proxy token issuer signed across a deactivation") {
            try await issuer.issueProxyServiceToken(
                issuer: Self.accountDID,
                audience: Self.peerDID,
                method: "app.bsky.feed.getTimeline",
                now: Date(timeIntervalSince1970: 1_750_000_000)
            )
        }
    }

    // MARK: F44 — space delegation token issuer

    func testDelegationTokenIssuerRefusesAfterDeactivationDuringKeyRead() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { try? await fixture.close() }

        let issuer = LocalAccountSpaceDelegationTokenIssuer(
            accounts: fixture.accounts,
            keyStore: fixture.deactivatingKeyStore()
        )
        await assertUnavailable("delegation issuer signed across a deactivation") {
            try await issuer.issueDelegation(
                space: try Self.space(),
                issuer: Self.accountDID,
                now: Date(timeIntervalSince1970: 1_750_000_000)
            )
        }
    }

    // MARK: F45 — repository commit signer

    func testRepositoryCommitSignerRefusesAfterDeactivationDuringKeyRead() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { try? await fixture.close() }

        let signer = LocalAccountSpaceRepositoryCommitSigner(
            accounts: fixture.accounts,
            keyStore: fixture.deactivatingKeyStore()
        )
        await assertUnavailable("commit signer signed across a deactivation") {
            try await signer.signRepositoryCommit(
                space: try Self.space(),
                author: Self.accountDID,
                wireRevision: "3laaaaaaaaaaa",
                commitment: Data(repeating: 0x11, count: 32)
            )
        }
    }

    // MARK: Regression — the fence must not refuse everything

    func testUnracedIssuanceStillSucceedsOnEveryFencedSigner() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { try? await fixture.close() }
        let now = Date(timeIntervalSince1970: 1_750_000_000)

        let service = try await LocalAccountSpaceServiceAuthenticationIssuer(
            accounts: fixture.accounts,
            keyStore: fixture.keyStore
        ).issue(
            issuer: Self.accountDID,
            audience: Self.peerDID,
            method: "com.atproto.space.notifyWrite",
            eventID: "fence-event",
            now: now
        )
        XCTAssertEqual(try SpaceServiceJWT.inspect(service).issuer, Self.accountDID)

        let proxy = try await LocalAccountProxyServiceTokenIssuer(
            accounts: fixture.accounts,
            keyStore: fixture.keyStore
        ).issueProxyServiceToken(
            issuer: Self.accountDID,
            audience: Self.peerDID,
            method: "app.bsky.feed.getTimeline",
            now: now
        )
        XCTAssertEqual(proxy.split(separator: ".").count, 3)

        let delegation = try await LocalAccountSpaceDelegationTokenIssuer(
            accounts: fixture.accounts,
            keyStore: fixture.keyStore
        ).issueDelegation(space: try Self.space(), issuer: Self.accountDID, now: now)
        XCTAssertEqual(delegation.split(separator: ".").count, 3)

        let envelope = try await LocalAccountSpaceRepositoryCommitSigner(
            accounts: fixture.accounts,
            keyStore: fixture.keyStore
        ).signRepositoryCommit(
            space: try Self.space(),
            author: Self.accountDID,
            wireRevision: "3laaaaaaaaaaa",
            commitment: Data(repeating: 0x11, count: 32)
        )
        XCTAssertEqual(envelope.context.author, Self.accountDID)
    }

    // MARK: F16 — service public-key resolution

    /// A deactivated managed account is a terminal negative, not an absence.
    /// Returning `nil` here is what lets the composite fall through to a pin.
    func testDeactivatedManagedIssuerIsTerminalNotAFallThrough() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { try? await fixture.close() }

        let resolver = LocalAccountSpaceServicePublicKeyResolver(
            accounts: fixture.accounts,
            publicKeyStore: fixture.keyStore
        )
        let active = try await resolver.publicKey(for: Self.accountDID)
        XCTAssertNotNil(active)

        _ = try await fixture.accounts.transitionStatus(
            did: Self.accountDID,
            to: .deactivated,
            now: Date()
        )
        await assertUnavailable("a deactivated managed issuer must not resolve as absent") {
            try await resolver.publicKey(for: Self.accountDID)
        }
    }

    /// The fall-through itself must survive: an unmanaged DID, and a
    /// syntactically invalid issuer, are both proven absences.
    func testUnmanagedAndMalformedIssuersStillFallThroughAsNil() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { try? await fixture.close() }

        let resolver = LocalAccountSpaceServicePublicKeyResolver(
            accounts: fixture.accounts,
            publicKeyStore: fixture.keyStore
        )
        let unmanaged = try await resolver.publicKey(for: Self.unmanagedDID)
        XCTAssertNil(unmanaged)
        let malformed = try await resolver.publicKey(for: "not-a-did")
        XCTAssertNil(malformed)
    }

    /// The finding as filed: an operator pin overlapping a locally managed DID
    /// keeps verifying service JWTs after that account is deactivated.
    func testOperatorPinDoesNotSurviveDeactivationOfTheOverlappingLocalAccount() async throws {
        let fixture = try await Fixture.make()
        addTeardownBlock { try? await fixture.close() }

        // The pin must agree with the live account key, or composition refuses
        // to build at all — that is the configuration the finding describes.
        let stored = try await fixture.keyStore.publicKey(for: fixture.signingReference)
        let encoded = try XCTUnwrap(stored)
        let pinned = try P256.Signing.PublicKey(x963Representation: encoded)
        let composite = try await CompositeSpaceServicePublicKeyResolver(
            local: LocalAccountSpaceServicePublicKeyResolver(
                accounts: fixture.accounts,
                publicKeyStore: fixture.keyStore
            ),
            pinned: [
                try PinnedSpaceServicePublicKey(
                    issuer: Self.accountDID,
                    generation: 1,
                    publicKey: pinned
                ),
            ]
        )
        let beforeDeactivation = try await composite.publicKey(for: Self.accountDID)
        XCTAssertNotNil(beforeDeactivation)

        _ = try await fixture.accounts.transitionStatus(
            did: Self.accountDID,
            to: .deactivated,
            now: Date()
        )
        await assertUnavailable("the pin outlived the local account it overlaps") {
            try await composite.publicKey(for: Self.accountDID)
        }
    }

    // MARK: Helpers

    private static func space() throws -> SpaceURI {
        try SpaceURI(
            authority: accountDID,
            spaceType: "app.bsky.bookmarks",
            skey: "fence"
        )
    }

    private func assertUnavailable<T>(
        _ message: String,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ expression: () async throws -> T
    ) async {
        do {
            _ = try await expression()
            XCTFail(message, file: file, line: line)
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

    /// Deactivates the account inside the key-store suspension.
    private actor DeactivatingKeyStore: AccountKeyStore {
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

    /// Rotates the signing key inside the key-store suspension, so the scalar
    /// already read belongs to a superseded generation.
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
        let signingReference: AccountKeyReference

        func deactivatingKeyStore() -> DeactivatingKeyStore {
            DeactivatingKeyStore(
                wrapped: keyStore,
                accounts: accounts,
                did: SignerLifecycleFenceTests.accountDID
            )
        }

        func rotatingKeyStore() -> RotatingKeyStore {
            RotatingKeyStore(
                wrapped: keyStore,
                control: control,
                did: SignerLifecycleFenceTests.accountDID
            )
        }

        static func make() async throws -> Fixture {
            let root = FileManager.default.temporaryDirectory
                .appending(path: "SignerLifecycleFenceTests-\(UUID().uuidString)")
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
                        activeKey: Data(repeating: 0x5C, count: 32)
                    )
                )
                let keys = try await AccountKeyProvisioner(keyStore: keyStore)
                    .provisionInitial(accountDID: SignerLifecycleFenceTests.accountDID)
                _ = try await control.createAccount(
                    try AccountControlRegistration(
                        did: SignerLifecycleFenceTests.accountDID,
                        canonicalHandle: "signer.example.com",
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
                    ),
                    signingReference: keys.signingReference
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
