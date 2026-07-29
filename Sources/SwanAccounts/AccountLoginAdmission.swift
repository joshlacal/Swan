import Crypto
import Foundation
import SwanStorage

public struct AccountLoginAdmissionKey: Sendable {
    fileprivate let bytes: Data

    public init(_ bytes: Data) throws {
        guard bytes.count == 32 else {
            throw AccountLoginAdmissionError.invalidConfiguration
        }
        self.bytes = bytes
    }
}

public struct AccountLoginAdmissionPolicy: Sendable, Equatable {
    public let handleAttempts: Int
    public let directPeerAttempts: Int
    public let pairAttempts: Int
    public let window: TimeInterval
    public let maximumProcessEntries: Int
    public let maximumDurableEntries: Int

    public init(
        handleAttempts: Int = 10,
        directPeerAttempts: Int = 100,
        pairAttempts: Int = 10,
        window: TimeInterval = 5 * 60,
        maximumProcessEntries: Int = 50_000,
        maximumDurableEntries: Int = 100_000
    ) throws {
        guard (1 ... 10_000).contains(handleAttempts),
              (1 ... 10_000).contains(directPeerAttempts),
              (1 ... 10_000).contains(pairAttempts),
              window.isFinite,
              (1 ... 86_400).contains(window),
              (3 ... 1_000_000).contains(maximumProcessEntries),
              (3 ... 1_000_000).contains(maximumDurableEntries) else {
            throw AccountLoginAdmissionError.invalidConfiguration
        }
        self.handleAttempts = handleAttempts
        self.directPeerAttempts = directPeerAttempts
        self.pairAttempts = pairAttempts
        self.window = window
        self.maximumProcessEntries = maximumProcessEntries
        self.maximumDurableEntries = maximumDurableEntries
    }
}

public enum AccountLoginAdmissionDecision: Sendable, Equatable {
    case allowed
    case rateLimited
}

public enum AccountLoginAdmissionError: Error, Sendable, Equatable {
    case invalidConfiguration
    case unavailable
}

/// Process-local and SQLite-backed admission for password login. Every
/// request consumes handle, accepted socket-peer, and pair buckets. Only
/// domain-separated HMAC digests cross the storage boundary.
public actor AccountLoginAdmissionService {
    private struct ProcessKey: Hashable {
        let scope: AccountLoginRateLimitScope
        let digest: Data
    }

    private struct ProcessBucket {
        var startedAt: Date
        var attempts: Int
    }

    private static let domain = Data("swan.account-login.rate-limit.v1\u{0}".utf8)
    // Invalid handles deliberately collapse to one non-text sentinel. Keeping
    // attacker-controlled invalid spellings distinct would let unauthenticated
    // traffic consume the bounded process and durable bucket tables.
    private static let invalidHandleSentinel = Data([0])

    private let store: any AccountLoginAdmissionStore
    private let key: AccountLoginAdmissionKey
    private let policy: AccountLoginAdmissionPolicy
    private var processBuckets: [ProcessKey: ProcessBucket] = [:]

    public init(
        store: any AccountLoginAdmissionStore,
        key: AccountLoginAdmissionKey,
        policy: AccountLoginAdmissionPolicy = try! .init()
    ) {
        self.store = store
        self.key = key
        self.policy = policy
    }

    public func admit(
        handle: String,
        directPeer: String,
        now: Date = Date()
    ) async throws -> AccountLoginAdmissionDecision {
        try Task.checkCancellation()
        let handleBytes = Array(handle.utf8)
        let peerBytes = Array(directPeer.utf8)
        guard (1 ... 253).contains(handleBytes.count),
              !handleBytes.contains(0),
              (1 ... 128).contains(peerBytes.count),
              peerBytes.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }),
              now.timeIntervalSince1970.isFinite,
              now.timeIntervalSince1970 >= 0 else {
            throw AccountLoginAdmissionError.unavailable
        }

        let normalizedHandle: Data
        if let canonicalHandle = try? AccountIdentifiers.canonicalHandle(handle) {
            normalizedHandle = Data(canonicalHandle.utf8)
        } else {
            normalizedHandle = Self.invalidHandleSentinel
        }
        let handleDigest = digest(
            scope: .handle,
            components: [normalizedHandle]
        )
        let peerDigest = digest(
            scope: .directPeer,
            components: [Data(peerBytes)]
        )
        let pairDigest = digest(
            scope: .handlePeerPair,
            components: [handleDigest, peerDigest]
        )
        let prepared = try [
            bucket(.handle, handleDigest, policy.handleAttempts),
            bucket(.directPeer, peerDigest, policy.directPeerAttempts),
            bucket(.handlePeerPair, pairDigest, policy.pairAttempts),
        ]

        let processLimited = try consumeProcess(prepared, now: now)
        if processLimited {
            return .rateLimited
        }
        let durable: AccountLoginRateLimitDecision
        do {
            durable = try await store.consumeLoginRateLimit(
                AccountLoginRateLimitRequest(
                    buckets: prepared,
                    maximumEntries: policy.maximumDurableEntries
                ),
                now: now
            )
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw AccountLoginAdmissionError.unavailable
        }

        switch durable {
        case .capacityExhausted:
            throw AccountLoginAdmissionError.unavailable
        case .limited:
            return .rateLimited
        case .allowed:
            return .allowed
        }
    }

    private func bucket(
        _ scope: AccountLoginRateLimitScope,
        _ digest: Data,
        _ maximumAttempts: Int
    ) throws -> AccountLoginRateLimitBucket {
        try AccountLoginRateLimitBucket(
            scope: scope,
            keyDigest: digest,
            maximumAttempts: maximumAttempts,
            window: policy.window
        )
    }

    private func consumeProcess(
        _ buckets: [AccountLoginRateLimitBucket],
        now: Date
    ) throws -> Bool {
        for bucket in buckets {
            let key = ProcessKey(scope: bucket.scope, digest: bucket.keyDigest)
            guard let current = processBuckets[key] else { continue }
            let age = now.timeIntervalSince(current.startedAt)
            guard age >= 0 else {
                throw AccountLoginAdmissionError.unavailable
            }
            if age < policy.window,
               current.attempts >= bucket.maximumAttempts {
                // Match the durable rule: once any existing dimension is
                // limited, do not allocate attacker-varied missing keys.
                return true
            }
        }

        let newKeys = buckets.reduce(into: 0) { count, bucket in
            let key = ProcessKey(scope: bucket.scope, digest: bucket.keyDigest)
            if processBuckets[key] == nil {
                count += 1
            }
        }
        if processBuckets.count + newKeys > policy.maximumProcessEntries {
            processBuckets = processBuckets.filter {
                now.timeIntervalSince($0.value.startedAt) < policy.window
            }
        }
        guard processBuckets.count + newKeys <= policy.maximumProcessEntries else {
            throw AccountLoginAdmissionError.unavailable
        }

        var limited = false
        for bucket in buckets {
            let key = ProcessKey(scope: bucket.scope, digest: bucket.keyDigest)
            guard var current = processBuckets[key],
                  now.timeIntervalSince(current.startedAt) < policy.window else {
                processBuckets[key] = ProcessBucket(startedAt: now, attempts: 1)
                continue
            }
            guard current.attempts < bucket.maximumAttempts else {
                limited = true
                continue
            }
            current.attempts += 1
            processBuckets[key] = current
        }
        return limited
    }

    private func digest(
        scope: AccountLoginRateLimitScope,
        components: [Data]
    ) -> Data {
        var input = Self.domain
        input.append(Data(scope.rawValue.utf8))
        for component in components {
            input.append(0)
            var length = UInt64(component.count).bigEndian
            withUnsafeBytes(of: &length) { input.append(contentsOf: $0) }
            input.append(component)
        }
        return Data(HMAC<SHA256>.authenticationCode(
            for: input,
            using: SymmetricKey(data: key.bytes)
        ))
    }
}
