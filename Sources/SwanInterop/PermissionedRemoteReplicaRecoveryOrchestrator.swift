import Crypto
import Foundation
import Petrel
import SwanCore
import SwanOAuth
import SwanSpaces
import SwanSQLite
import SwanStorage

/// An already-authenticated source session for one remote permissioned
/// repository.  The session carries the exact key used to verify the CAR and
/// a freshness witness obtained from the same authenticated source before the
/// stream was opened.  Callers cannot provide a free-form verifier label that
/// differs from the key fingerprint.
private actor PermissionedRemoteReplicaSourceCloseGate {
    private let action: @Sendable () async -> Void
    private var closed = false

    init(action: @escaping @Sendable () async -> Void) {
        self.action = action
    }

    func close() async {
        guard !closed else { return }
        closed = true
        await action()
    }
}

public struct PermissionedRemoteReplicaSourceSession: Sendable {
    public let identity: PermissionedRemoteReplicaSourceIdentity
    public let verificationKey: PermissionedDataJWTVerificationKey
    public let freshnessWitness: PermissionedRemoteReplicaFreshnessWitness
    public let source: any SpaceCARRecoveryByteSource
    /// Releases the source descriptor and any temporary transport spool. The
    /// orchestrator invokes this on both verification success and failure.
    /// The gate below makes the callback exactly-once even when a publication
    /// failure races the verification cleanup path.
    private let closeGate: PermissionedRemoteReplicaSourceCloseGate

    public init(
        identity: PermissionedRemoteReplicaSourceIdentity,
        verificationKey: PermissionedDataJWTVerificationKey,
        freshnessWitness: PermissionedRemoteReplicaFreshnessWitness,
        source: any SpaceCARRecoveryByteSource,
        closeSource: @escaping @Sendable () async -> Void
    ) throws {
        guard identity.verifierIdentity == verificationKey.recoveryVerifierIdentity else {
            throw PermissionedRemoteReplicaRecoveryError.invalidBinding
        }
        self.identity = identity
        self.verificationKey = verificationKey
        self.freshnessWitness = freshnessWitness
        self.source = source
        self.closeGate = PermissionedRemoteReplicaSourceCloseGate(
            action: closeSource
        )
    }

    fileprivate func close() async {
        await closeGate.close()
    }
}

/// The network adapter boundary for production recovery.  Implementations
/// authenticate the source origin, resolve its repository signing key through
/// the configured trust policy, obtain a signed current-head witness, and then
/// return a one-shot bounded CAR byte source.  The orchestrator never performs
/// network I/O from a SQLite transaction.
public protocol PermissionedRemoteReplicaSourceProvider: Sendable {
    func openPermissionedRemoteReplicaSource(
        target: PermissionedRemoteReplicaTarget
    ) async throws -> PermissionedRemoteReplicaSourceSession
}

/// Durable, caller-bound full-CAR recovery.  The caller supplies an
/// authenticated source session; this type derives the persisted source
/// origin/verifier binding from that session, stages through the durable
/// SQLite boundary, and publishes only after the streaming verifier has
/// authenticated the roots, commitment, records, and freshness witness.
public struct PermissionedRemoteReplicaRecoveryOrchestrator: Sendable {
    public typealias Staging = any SpaceCARRecoveryIndex & SpaceCARRecoveryRecordSink
    public typealias StagingFactory = @Sendable (String) -> Staging
    public typealias Clock = @Sendable () -> Int64
    public typealias PublicationAuthorization = @Sendable (
        @escaping @Sendable () async throws
            -> CommittedPermissionedRemoteReplicaRecovery
    ) async throws -> CommittedPermissionedRemoteReplicaRecovery

    private let store: any PermissionedRemoteReplicaRecoveryStore
    private let stagingFactory: StagingFactory
    private let now: Clock
    private let publicationAuthorization: PublicationAuthorization?

    public init(
        store: any PermissionedRemoteReplicaRecoveryStore,
        stagingFactory: @escaping StagingFactory,
        now: @escaping Clock = {
            Int64(Date().timeIntervalSince1970)
        },
        publicationAuthorization: PublicationAuthorization? = nil
    ) {
        self.store = store
        self.stagingFactory = stagingFactory
        self.now = now
        self.publicationAuthorization = publicationAuthorization
    }

    /// Convenience for the production per-account SQLite store.  The staging
    /// index and record sink share one session-scoped database actor and retain
    /// no repository-wide values in process memory.
    public init(
        database: SQLiteAccountDatabase,
        now: @escaping Clock = {
            Int64(Date().timeIntervalSince1970)
        },
        publicationAuthorization: PublicationAuthorization? = nil
    ) {
        self.init(
            store: database,
            stagingFactory: { sessionID in
                SQLitePermissionedRemoteReplicaRecoveryStaging(
                    database: database,
                    sessionID: sessionID,
                    now: now
                )
            },
            now: now,
            publicationAuthorization: publicationAuthorization
        )
    }

    /// Opens no source itself; the provider/session boundary is deliberately
    /// explicit so a caller cannot accidentally persist request-selected
    /// origin or key text.  A provider-backed overload below is the normal
    /// production entry point.
    public func recover(
        target: PermissionedRemoteReplicaTarget,
        requestID: String,
        source: PermissionedRemoteReplicaSourceSession,
        profileID: String,
        expiresAt: Int64,
        limits: SpaceCARRecoveryLimits = .standard
    ) async throws -> CommittedPermissionedRemoteReplicaRecovery {
        do {
            let createdAt = now()
            guard expiresAt > createdAt else {
                throw PermissionedRemoteReplicaRecoveryError.expiredSession
            }
            guard source.identity.repositoryDID == target.repositoryDID else {
                throw PermissionedRemoteReplicaRecoveryError.receiverMismatch
            }
            let expectedBase = try await store.permissionedRemoteReplicaHead(
                target: target
            )
            let requestDigest = Self.requestDigest(
                requestID: requestID,
                target: target,
                source: source.identity,
                freshness: source.freshnessWitness,
                expectedBase: expectedBase,
                profileID: profileID,
                limits: limits
            )
            let binding = try PermissionedRemoteReplicaImportBinding(
                requestID: requestID,
                requestDigest: requestDigest,
                source: source.identity,
                target: target,
                expectedBase: expectedBase,
                freshnessWitness: source.freshnessWitness,
                profileID: profileID,
                limits: limits
            )
            let outcome = try await store.createPermissionedRemoteReplicaImportSession(
                binding: binding,
                createdAt: createdAt,
                expiresAt: expiresAt,
                now: createdAt
            )
            switch outcome {
            case let .committed(committed):
                // Provider-backed sessions own a CAR descriptor and a spool
                // lease even when durable request replay means no new read is
                // needed.  Close before returning so idempotent retries do
                // not leak files or disk admission.
                await source.close()
                return committed
            case let .staged(session):
                guard session.binding == binding else {
                    await store.poisonPermissionedRemoteReplicaImportSession(
                        id: session.id
                    )
                    throw PermissionedRemoteReplicaRecoveryError.bindingMismatch
                }
                return try await stageAndPublish(
                    sessionID: session.id,
                    target: target,
                    source: source,
                    limits: limits
                )
            }
        } catch {
            // `stageAndPublish` also closes on its terminal paths, but the
            // outer boundary must cover failures before staging begins (bad
            // expiry, CAS/binding rejection, or durable-session replay).
            await source.close()
            throw error
        }
    }

    /// Provider-backed convenience that keeps source authentication outside
    /// the durable boundary while making the intended call sequence explicit.
    public func recover(
        target: PermissionedRemoteReplicaTarget,
        requestID: String,
        provider: any PermissionedRemoteReplicaSourceProvider,
        profileID: String,
        expiresAt: Int64,
        limits: SpaceCARRecoveryLimits = .standard
    ) async throws -> CommittedPermissionedRemoteReplicaRecovery {
        let source = try await provider.openPermissionedRemoteReplicaSource(
            target: target
        )
        return try await recover(
            target: target,
            requestID: requestID,
            source: source,
            profileID: profileID,
            expiresAt: expiresAt,
            limits: limits
        )
    }

    private func stageAndPublish(
        sessionID: String,
        target: PermissionedRemoteReplicaTarget,
        source: PermissionedRemoteReplicaSourceSession,
        limits: SpaceCARRecoveryLimits
    ) async throws -> CommittedPermissionedRemoteReplicaRecovery {
        let staging = stagingFactory(sessionID)
        do {
            let verification = try await SpaceCARCodec.verifyStreamingRecovery(
                from: source.source,
                space: target.space,
                author: target.repositoryDID,
                contextSignatureVerifier: { envelope in
                    let signingInput = try SpaceCommitCodec.contextSigningBytes(
                        envelope.context
                    )
                    let algorithm: String = switch source.verificationKey {
                    case .p256: "ES256"
                    case .secp256k1PublicKey: "ES256K"
                    }
                    return try source.verificationKey.verify(
                        signature: envelope.contextSignature,
                        signingInput: signingInput,
                        algorithm: algorithm
                    )
                },
                index: staging,
                recordSink: staging,
                limits: limits
            )
            await source.close()
            let verifiedAt = now()
            try await store.markPermissionedRemoteReplicaImportVerified(
                sessionID: sessionID,
                verification: verification,
                now: verifiedAt
            )
            let publish: @Sendable () async throws
                -> CommittedPermissionedRemoteReplicaRecovery = {
                    try await store.publishVerifiedPermissionedRemoteReplicaRecovery(
                        sessionID: sessionID,
                        consumedAt: verifiedAt,
                        now: now()
                    )
                }
            if let publicationAuthorization {
                return try await publicationAuthorization(publish)
            }
            return try await publish()
        } catch {
            await source.close()
            await store.poisonPermissionedRemoteReplicaImportSession(
                id: sessionID
            )
            try? await store.cleanupPermissionedRemoteReplicaImportSession(
                id: sessionID
            )
            throw error
        }
    }

    private static func requestDigest(
        requestID: String,
        target: PermissionedRemoteReplicaTarget,
        source: PermissionedRemoteReplicaSourceIdentity,
        freshness: PermissionedRemoteReplicaFreshnessWitness,
        expectedBase: PermissionedRemoteReplicaHead?,
        profileID: String,
        limits: SpaceCARRecoveryLimits
    ) -> Data {
        var material = Data("swan.permissioned-remote-recovery.v1\0".utf8)
        for value in [
            requestID,
            target.receiverDID,
            target.space.rawValue,
            target.repositoryDID,
            source.origin,
            source.repositoryDID,
            source.verifierIdentity,
            freshness.wireRevision.toString(),
            Hex.encode(freshness.commitment),
            profileID,
            String(limits.maximumCARBytes),
            String(limits.maximumRecordBytes),
            String(limits.maximumIndexEntries),
            String(limits.maximumUniqueBlocks),
        ] {
            material.append(contentsOf: value.utf8)
            material.append(0)
        }
        if let expectedBase {
            for value in [
                "base-present",
                String(expectedBase.generation),
                expectedBase.wireRevision.toString(),
                expectedBase.historyFloorWireRevision.toString(),
                Hex.encode(expectedBase.ltHash),
                Hex.encode(expectedBase.commitment),
                Hex.encode(expectedBase.stateMarker),
            ] {
                material.append(contentsOf: value.utf8)
                material.append(0)
            }
        } else {
            material.append(contentsOf: "base-none\0".utf8)
        }
        return Data(SHA256.hash(data: material))
    }
}
