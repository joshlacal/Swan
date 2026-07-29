import Crypto
import Foundation
@testable import SwanAccounts
@testable import SwanOAuth
import SwanCore
import SwanSQLite
import SwanStorage
import XCTest

final class PLCSpaceCredentialPublicKeyResolverTests: XCTestCase, @unchecked Sendable {
    private let issuer = "did:plc:abcdefghijklmnopqrstuvwx"
    private let referenceSecp256k1Key =
        "did:key:zQ3shqwJEJyMBsBXCWyCBpUBMqxcon9oHB7mCvx4sSpMdLJwc"
    private let auditSigningKey = P256.Signing.PrivateKey()

    func testResolvesDedicatedP256AndFallbackSecp256k1Keys() async throws {
        let privateKey = P256.Signing.PrivateKey()
        let p256 = privateKey.publicKey
        let plc = ResolverPLCFixture(snapshots: [
            issuer: try snapshot(methods: [
                "atproto_space": P256DIDKey(publicKey: p256).value,
                "atproto": referenceSecp256k1Key,
            ]),
        ])
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: ResolverCheckpointStore()
        )

        let dedicatedKey = try await resolver.publicKey(
            for: issuer,
            keyID: PermissionedDataJWT.spaceCredentialKeyID
        )
        let dedicated = try XCTUnwrap(dedicatedKey)
        let fallbackKey = try await resolver.publicKey(
            for: issuer,
            keyID: PermissionedDataJWT.spaceCredentialFallbackKeyID
        )
        let fallback = try XCTUnwrap(fallbackKey)

        XCTAssertEqual(
            dedicated.deterministicIdentity,
            PermissionedDataJWTVerificationKey.p256(p256).deterministicIdentity
        )
        XCTAssertTrue(try dedicated.verify(
            signature: P256WireSignature.sign(
                Data("credential".utf8),
                using: privateKey
            ),
            signingInput: Data("credential".utf8),
            algorithm: "ES256"
        ))
        switch fallback {
        case let .secp256k1PublicKey(actual):
            guard case let .secp256k1(expected) =
                try PLCDIDKeyCodec.decode(referenceSecp256k1Key) else {
                return XCTFail("fixture key must be secp256k1")
            }
            XCTAssertEqual(actual, expected)
        case .p256:
            XCTFail("expected PLC secp256k1 fallback key")
        }
        let fetchCount = await plc.fetchCount()
        XCTAssertEqual(fetchCount, 1, "one PLC state serves both key IDs")
    }

    func testUnknownIssuerAndKeyFailClosedWithoutUnsafeFallback() async throws {
        let plc = ResolverPLCFixture(snapshots: [
            issuer: try snapshot(methods: ["atproto": referenceSecp256k1Key]),
        ])
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: ResolverCheckpointStore()
        )

        let invalidIssuer = try await resolver.publicKey(for: "https://example.invalid", keyID: "#atproto")
        let invalidKey = try await resolver.publicKey(for: issuer, keyID: "#arbitrary")
        XCTAssertNil(invalidIssuer)
        XCTAssertNil(invalidKey)
        let noFetches = await plc.fetchCount()
        XCTAssertEqual(noFetches, 0, "invalid issuer/key must not initiate resolution")

        let unknownKey = try await resolver.publicKey(
            for: issuer,
            keyID: PermissionedDataJWT.spaceCredentialKeyID
        )
        XCTAssertNil(unknownKey)
        let fetchCount = await plc.fetchCount()
        XCTAssertEqual(fetchCount, 1)
    }

    func testConfiguredIssuerAllowlistRejectsUntrustedSpaceAuthorityWithoutFetch() async throws {
        let untrustedIssuer = "did:plc:bcdefghijklmnopqrstuvwxy"
        let plc = ResolverPLCFixture(snapshots: [
            issuer: try snapshot(methods: ["atproto": referenceSecp256k1Key]),
        ])
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: ResolverCheckpointStore(),
            allowedIssuers: [issuer]
        )

        let resolved = try await resolver.publicKey(
            for: untrustedIssuer,
            keyID: PermissionedDataJWT.spaceCredentialKeyID
        )

        XCTAssertNil(resolved)
        let fetchCount = await plc.fetchCount()
        XCTAssertEqual(fetchCount, 0)
    }

    func testExpiredCacheIsNotUsedWhenRefreshFailsThenCanRecover() async throws {
        let clock = ResolverClock(Date(timeIntervalSince1970: 1_750_000_000))
        let key = P256.Signing.PrivateKey().publicKey
        let plc = ResolverPLCFixture(snapshots: [
            issuer: try snapshot(methods: [
                "atproto_space": P256DIDKey(publicKey: key).value,
            ]),
        ])
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: ResolverCheckpointStore(),
            cacheConfiguration: .init(
                lifetime: 10,
                maximumEntries: 1,
                negativeLifetime: 1
            ),
            clock: { clock.now() }
        )

        let initial = try await resolver.publicKey(for: issuer, keyID: "#atproto_space")
        XCTAssertNotNil(initial)
        clock.advance(by: 11)
        await plc.failNextFetch()
        await XCTAssertThrowsErrorAsync(
            try await resolver.publicKey(for: issuer, keyID: "#atproto_space")
        )
        let failedRefreshCount = await plc.fetchCount()
        XCTAssertEqual(failedRefreshCount, 2)

        // A short negative entry damps retries without reviving stale material.
        await XCTAssertThrowsErrorAsync(
            try await resolver.publicKey(for: issuer, keyID: "#atproto_space")
        )
        let dampedFetchCount = await plc.fetchCount()
        XCTAssertEqual(dampedFetchCount, 2)
        clock.advance(by: 2)

        // A request after the negative-cache interval fetches again and only
        // then repopulates the positive cache.
        let recovered = try await resolver.publicKey(for: issuer, keyID: "#atproto_space")
        XCTAssertNotNil(recovered)
        let recoveredFetchCount = await plc.fetchCount()
        XCTAssertEqual(recoveredFetchCount, 3)
        let cached = try await resolver.publicKey(for: issuer, keyID: "#atproto_space")
        XCTAssertNotNil(cached)
        let cachedFetchCount = await plc.fetchCount()
        XCTAssertEqual(cachedFetchCount, 3)
    }

    func testConcurrentRequestsForOneIssuerShareOnePLCRefresh() async throws {
        let key = P256.Signing.PrivateKey().publicKey
        let plc = ResolverPLCFixture(
            snapshots: [
                issuer: try snapshot(methods: [
                    "atproto_space": P256DIDKey(publicKey: key).value,
                ]),
            ],
            fetchDelayNanoseconds: 100_000_000
        )
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: ResolverCheckpointStore()
        )

        try await withThrowingTaskGroup(of: Data.self) { group in
            for _ in 0 ..< 24 {
                group.addTask {
                    let maybeResolved = try await resolver.publicKey(
                        for: self.issuer,
                        keyID: "#atproto_space"
                    )
                    let resolved = try XCTUnwrap(maybeResolved)
                    return resolved.deterministicIdentity
                }
            }
            var identities = [Data]()
            for try await identity in group {
                identities.append(identity)
            }
            XCTAssertEqual(identities.count, 24)
            XCTAssertEqual(Set(identities).count, 1)
        }
        let fetchCount = await plc.fetchCount()
        let peakFetchCount = await plc.peakConcurrentFetchCount()
        XCTAssertEqual(fetchCount, 1)
        XCTAssertEqual(peakFetchCount, 1)
    }

    func testConcurrentDistinctIssuerLookupsAreRejectedAtAdmissionBound() async throws {
        let issuers = [
            "did:plc:abcdefghijklmnopqrstuvw2",
            "did:plc:abcdefghijklmnopqrstuvw3",
            "did:plc:abcdefghijklmnopqrstuvw4",
            "did:plc:abcdefghijklmnopqrstuvw5",
            "did:plc:abcdefghijklmnopqrstuvw6",
            "did:plc:bcdefghijklmnopqrstuvwxy",
        ]
        let key = P256.Signing.PrivateKey().publicKey
        var snapshots = [String: ResolverPLCSnapshot]()
        for issuer in issuers {
            snapshots[issuer] = try snapshot(
                issuer: issuer,
                methods: ["atproto_space": P256DIDKey(publicKey: key).value]
            )
        }
        let plc = ResolverPLCFixture(
            snapshots: snapshots,
            fetchDelayNanoseconds: 100_000_000
        )
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: ResolverCheckpointStore(),
            cacheConfiguration: .init(maximumConcurrentLookups: 2)
        )

        let successes = await withTaskGroup(of: Bool.self) { group in
            for issuer in issuers {
                group.addTask {
                    do {
                        return try await resolver.publicKey(
                            for: issuer,
                            keyID: "#atproto_space"
                        ) != nil
                    } catch {
                        return false
                    }
                }
            }
            var successes = 0
            for await succeeded in group where succeeded {
                successes += 1
            }
            return successes
        }

        XCTAssertEqual(successes, 2)
        let fetchCount = await plc.fetchCount()
        let peakFetchCount = await plc.peakConcurrentFetchCount()
        XCTAssertEqual(fetchCount, 2)
        XCTAssertEqual(peakFetchCount, 2)
    }

    func testUnknownIssuerFailureIsNegativelyCached() async throws {
        let clock = ResolverClock(Date(timeIntervalSince1970: 1_750_000_000))
        let missingIssuer = "did:plc:bcdefghijklmnopqrstuvwxy"
        let plc = ResolverPLCFixture(snapshots: [:])
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: ResolverCheckpointStore(),
            cacheConfiguration: .init(negativeLifetime: 10),
            clock: { clock.now() }
        )

        await XCTAssertThrowsErrorAsync(
            try await resolver.publicKey(for: missingIssuer, keyID: "#atproto_space")
        )
        await XCTAssertThrowsErrorAsync(
            try await resolver.publicKey(for: missingIssuer, keyID: "#atproto_space")
        )
        let cachedFailureFetchCount = await plc.fetchCount()
        XCTAssertEqual(cachedFailureFetchCount, 1)

        clock.advance(by: 11)
        await XCTAssertThrowsErrorAsync(
            try await resolver.publicKey(for: missingIssuer, keyID: "#atproto_space")
        )
        let expiredFailureFetchCount = await plc.fetchCount()
        XCTAssertEqual(expiredFailureFetchCount, 2)
    }

    func testNewIssuerBudgetBoundsSequentialOutboundLookups() async throws {
        let clock = ResolverClock(Date(timeIntervalSince1970: 1_750_000_000))
        let issuers = [
            "did:plc:abcdefghijklmnopqrstuvw2",
            "did:plc:abcdefghijklmnopqrstuvw3",
            "did:plc:abcdefghijklmnopqrstuvw4",
        ]
        let key = P256.Signing.PrivateKey().publicKey
        var snapshots = [String: ResolverPLCSnapshot]()
        for issuer in issuers {
            snapshots[issuer] = try snapshot(
                issuer: issuer,
                methods: ["atproto_space": P256DIDKey(publicKey: key).value]
            )
        }
        let plc = ResolverPLCFixture(snapshots: snapshots)
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: ResolverCheckpointStore(),
            cacheConfiguration: .init(maximumNewIssuerLookupsPerMinute: 2),
            clock: { clock.now() }
        )

        for issuer in issuers.prefix(2) {
            let resolved = try await resolver.publicKey(
                for: issuer,
                keyID: "#atproto_space"
            )
            XCTAssertNotNil(resolved)
        }
        await XCTAssertThrowsErrorAsync(
            try await resolver.publicKey(for: issuers[2], keyID: "#atproto_space")
        )
        let boundedFetchCount = await plc.fetchCount()
        XCTAssertEqual(boundedFetchCount, 2)

        clock.advance(by: 61)
        let afterWindow = try await resolver.publicKey(
            for: issuers[2],
            keyID: "#atproto_space"
        )
        XCTAssertNotNil(afterWindow)
        let resetWindowFetchCount = await plc.fetchCount()
        XCTAssertEqual(resetWindowFetchCount, 3)
    }

    func testRefreshAcceptsKeyRotationButRejectsHistoricalAuditRollback() async throws {
        let clock = ResolverClock(Date(timeIntervalSince1970: 1_750_000_000))
        let oldKey = P256.Signing.PrivateKey().publicKey
        let newKey = P256.Signing.PrivateKey().publicKey
        let initial = try snapshot(methods: [
            "atproto_space": P256DIDKey(publicKey: oldKey).value,
        ])
        let rotated = try snapshot(
            methods: ["atproto_space": P256DIDKey(publicKey: newKey).value],
            extending: initial
        )
        let plc = ResolverPLCFixture(snapshots: [issuer: initial])
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: plc,
            continuityStore: ResolverCheckpointStore(),
            cacheConfiguration: .init(
                lifetime: 10,
                maximumEntries: 1,
                negativeLifetime: 1
            ),
            clock: { clock.now() }
        )

        let maybeFirst = try await resolver.publicKey(
            for: issuer,
            keyID: "#atproto_space"
        )
        let first = try XCTUnwrap(maybeFirst)
        XCTAssertEqual(
            first.deterministicIdentity,
            PermissionedDataJWTVerificationKey.p256(oldKey).deterministicIdentity
        )

        await plc.setSnapshot(rotated, for: issuer)
        clock.advance(by: 11)
        let maybeRefreshed = try await resolver.publicKey(
            for: issuer,
            keyID: "#atproto_space"
        )
        let refreshed = try XCTUnwrap(maybeRefreshed)
        XCTAssertEqual(
            refreshed.deterministicIdentity,
            PermissionedDataJWTVerificationKey.p256(newKey).deterministicIdentity
        )

        // Request-selected churn cannot evict the authenticated terminal-CID
        // anchor, even after its value TTL has elapsed.
        let unrelatedIssuer = "did:plc:bcdefghijklmnopqrstuvwxy"
        await XCTAssertThrowsErrorAsync(
            try await resolver.publicKey(
                for: unrelatedIssuer,
                keyID: "#atproto_space"
            )
        )
        let afterChurnFetchCount = await plc.fetchCount()
        XCTAssertEqual(afterChurnFetchCount, 2)

        // The old prefix is independently valid, but it omits the terminal
        // operation already authenticated by this resolver.
        await plc.setSnapshot(initial, for: issuer)
        clock.advance(by: 11)
        await XCTAssertThrowsErrorAsync(
            try await resolver.publicKey(for: issuer, keyID: "#atproto_space")
        )
        let rollbackFetchCount = await plc.fetchCount()
        XCTAssertEqual(rollbackFetchCount, 3)
    }

    func testDurableCheckpointRejectsHistoricalPrefixAcrossResolverRestart() async throws {
        let root = FileManager.default.temporaryDirectory.appending(
            path: "PLCSpaceCredentialPublicKeyResolverTests-\(UUID().uuidString)"
        )
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let initial = try snapshot(methods: [
            "atproto_space": P256DIDKey(
                publicKey: P256.Signing.PrivateKey().publicKey
            ).value,
        ])
        let rotated = try snapshot(
            methods: [
                "atproto_space": P256DIDKey(
                    publicKey: P256.Signing.PrivateKey().publicKey
                ).value,
            ],
            extending: initial
        )

        var control: SQLiteControlDatabase? = try await SQLiteControlDatabase(
            dataDirectory: root
        )
        do {
            do {
                let resolver = try PLCSpaceCredentialPublicKeyResolver(
                    plc: ResolverPLCFixture(snapshots: [issuer: rotated]),
                    continuityStore: try XCTUnwrap(control)
                )
                let resolved = try await resolver.publicKey(
                    for: issuer,
                    keyID: "#atproto_space"
                )
                XCTAssertNotNil(resolved)
            }
            let rotatedTerminal = try XCTUnwrap(rotated.audit.last).cid
            let firstControl = try XCTUnwrap(control)
            let firstCheckpoint =
                try await firstControl.plcCredentialKeyContinuityCheckpoint(
                    for: issuer
                )
            XCTAssertEqual(
                firstCheckpoint?.terminalCID,
                rotatedTerminal
            )
            try await firstControl.close()
            control = nil

            control = try await SQLiteControlDatabase(dataDirectory: root)
            let reopenedControl = try XCTUnwrap(control)
            let restartedResolver = try PLCSpaceCredentialPublicKeyResolver(
                plc: ResolverPLCFixture(snapshots: [issuer: initial]),
                continuityStore: reopenedControl
            )
            await XCTAssertThrowsErrorAsync(
                try await restartedResolver.publicKey(
                    for: issuer,
                    keyID: "#atproto_space"
                )
            )
            let retainedCheckpoint =
                try await reopenedControl.plcCredentialKeyContinuityCheckpoint(
                    for: issuer
                )
            XCTAssertEqual(
                retainedCheckpoint?.terminalCID,
                rotatedTerminal
            )
            try await reopenedControl.close()
            control = nil
        } catch {
            if let control {
                try? await control.close()
            }
            throw error
        }
    }

    func testResolverRejectsCheckpointConfirmationForDifferentTerminal() async throws {
        let verificationKey = P256.Signing.PrivateKey().publicKey
        let current = try snapshot(methods: [
            "atproto_space": P256DIDKey(publicKey: verificationKey).value,
        ])
        let unrelated = try snapshot(methods: [
            "atproto_space": P256DIDKey(
                publicKey: P256.Signing.PrivateKey().publicKey
            ).value,
        ])
        let unrelatedTerminal = try XCTUnwrap(unrelated.audit.last).cid
        let continuityStore = ResolverMismatchingCheckpointStore(
            returned: try .init(
                issuer: issuer,
                terminalCID: unrelatedTerminal
            )
        )
        let resolver = try PLCSpaceCredentialPublicKeyResolver(
            plc: ResolverPLCFixture(snapshots: [issuer: current]),
            continuityStore: continuityStore
        )

        do {
            let key = try await resolver.publicKey(
                for: issuer,
                keyID: "#atproto_space"
            )
            XCTFail(
                "resolver returned \(String(describing: key)) before the exact terminal checkpoint was confirmed"
            )
        } catch {
            guard let swanError = error as? SwanError,
                  case .unavailable = swanError else {
                return XCTFail("expected unavailable, got \(error)")
            }
        }
    }

    func testConfigurationKeepsPLCLaboratoryOriginPolicy() throws {
        XCTAssertNoThrow(try PLCSpaceCredentialPublicKeyResolver(
            configuration: .laboratory(
                origin: URL(string: "http://127.0.0.1:2582")!
            ),
            continuityStore: ResolverCheckpointStore()
        ))
        XCTAssertThrowsError(try PLCClientConfiguration.laboratory(
            origin: URL(string: "http://192.168.1.10:2582")!
        ))
    }

    private func snapshot(
        issuer: String? = nil,
        methods: [String: String],
        extending previous: ResolverPLCSnapshot? = nil
    ) throws -> ResolverPLCSnapshot {
        let issuer = issuer ?? self.issuer
        let rotationKey = P256DIDKey(publicKey: auditSigningKey.publicKey).value
        let previousOperation = previous?.audit.last?.operation
        let unsigned = try PLCUnsignedRegularOperation(
            rotationKeys: [rotationKey],
            verificationMethods: methods,
            alsoKnownAs: [],
            services: [:],
            prev: try previousOperation?.cid.string
        )
        let operation = try PLCOperationCodec.sign(
            .regular(unsigned),
            using: auditSigningKey
        )
        let state = PLCDocumentData(
            did: issuer,
            rotationKeys: unsigned.rotationKeys,
            verificationMethods: methods,
            alsoKnownAs: unsigned.alsoKnownAs,
            services: unsigned.services
        )
        let entry = PLCAuditEntry(
            did: issuer,
            operation: operation,
            cid: try operation.cid.string,
            nullified: false,
            createdAt: previous == nil
                ? "2026-07-30T00:00:00.000Z"
                : "2026-07-30T00:00:01.000Z"
        )
        return ResolverPLCSnapshot(
            state: state,
            audit: (previous?.audit ?? []) + [entry]
        )
    }
}

private final class ResolverClock: @unchecked Sendable {
    private var value: Date
    private let lock = NSLock()

    init(_ value: Date) { self.value = value }
    func now() -> Date {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
    func advance(by interval: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        value.addTimeInterval(interval)
    }
}

private struct ResolverPLCSnapshot: Sendable {
    let state: PLCDocumentData
    let audit: [PLCAuditEntry]
}

private actor ResolverCheckpointStore: PLCCredentialKeyContinuityStore {
    private var checkpoints:
        [String: PLCCredentialKeyContinuityCheckpoint] = [:]

    func advancePLCCredentialKeyContinuity(
        _ advance: PLCCredentialKeyContinuityAdvance
    ) async throws -> PLCCredentialKeyContinuityCheckpoint {
        if let existing = checkpoints[advance.checkpoint.issuer],
           existing.terminalCID != advance.checkpoint.terminalCID,
           !advance.auditCIDs.contains(existing.terminalCID) {
            throw PLCCredentialKeyContinuityStoreError.continuityViolation
        }
        checkpoints[advance.checkpoint.issuer] = advance.checkpoint
        return advance.checkpoint
    }

    func plcCredentialKeyContinuityCheckpoint(
        for issuer: String
    ) async throws -> PLCCredentialKeyContinuityCheckpoint? {
        checkpoints[issuer]
    }
}

private actor ResolverMismatchingCheckpointStore:
    PLCCredentialKeyContinuityStore
{
    private let returned: PLCCredentialKeyContinuityCheckpoint

    init(returned: PLCCredentialKeyContinuityCheckpoint) {
        self.returned = returned
    }

    func advancePLCCredentialKeyContinuity(
        _ advance: PLCCredentialKeyContinuityAdvance
    ) async throws -> PLCCredentialKeyContinuityCheckpoint {
        returned
    }

    func plcCredentialKeyContinuityCheckpoint(
        for issuer: String
    ) async throws -> PLCCredentialKeyContinuityCheckpoint? {
        returned
    }
}

private actor ResolverPLCFixture: PLCClient {
    private var snapshots: [String: ResolverPLCSnapshot]
    private let fetchDelayNanoseconds: UInt64
    private var calls = 0
    private var failsNext = false
    private var activeFetches = 0
    private var peakActiveFetches = 0

    init(
        snapshots: [String: ResolverPLCSnapshot],
        fetchDelayNanoseconds: UInt64 = 0
    ) {
        self.snapshots = snapshots
        self.fetchDelayNanoseconds = fetchDelayNanoseconds
    }

    func submit(did _: String, operation _: PLCSignedOperation) async throws {
        throw SwanError.unavailable("fixture PLC does not accept writes")
    }

    func fetchState(did: String) async throws -> PLCDocumentData {
        calls += 1
        activeFetches += 1
        peakActiveFetches = max(peakActiveFetches, activeFetches)
        defer { activeFetches -= 1 }
        if failsNext {
            failsNext = false
            throw SwanError.unavailable("fixture PLC is unavailable")
        }
        if fetchDelayNanoseconds > 0 {
            try await Task.sleep(nanoseconds: fetchDelayNanoseconds)
        }
        guard let snapshot = snapshots[did] else {
            throw SwanError.unavailable("fixture PLC has no such DID")
        }
        return snapshot.state
    }

    func fetchAudit(did: String) async throws -> [PLCAuditEntry] {
        guard let snapshot = snapshots[did] else {
            throw SwanError.unavailable("fixture PLC has no such DID")
        }
        return snapshot.audit
    }

    func fetchAuditIfPresent(did: String) async throws -> [PLCAuditEntry]? {
        snapshots[did]?.audit
    }

    func fetchCount() -> Int { calls }
    func peakConcurrentFetchCount() -> Int { peakActiveFetches }
    func failNextFetch() { failsNext = true }
    func setSnapshot(_ snapshot: ResolverPLCSnapshot, for issuer: String) {
        snapshots[issuer] = snapshot
    }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected an error", file: file, line: line)
    } catch {}
}
