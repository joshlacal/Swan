import Crypto
import Foundation
import PetrelPLC
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

    /// The ratio of the default `handleAttempts` to the default
    /// `pairAttempts` is the number of distinct source addresses an attacker
    /// needs before it can lock a handle for everybody else. Smaller values
    /// remain constructible for tests; only the defaults are the deployed
    /// policy.
    ///
    /// Equal budgets made the handle bucket contribute no brute-force
    /// protection a single source did not already face from its own pair
    /// bucket, while granting that one source a repeatable handle-wide
    /// lockout: ten wrong passwords per window denied the account's real
    /// owner from every other address. Ten times the pair budget leaves the
    /// per-source guessing rate unchanged and raises the cost of the lockout
    /// from one address to ten.
    ///
    /// The handle-wide ceiling this sets is 100 guesses per five-minute
    /// window, i.e. 28,800 per day against Argon2id, up from 2,880.
    public init(
        handleAttempts: Int = 100,
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

public enum OAuthPeerAdmissionDecision: Sendable, Equatable {
    case allowed
    case rateLimited
}

/// Per-peer request budget for the unauthenticated OAuth protocol endpoints.
///
/// PAR, token, and revocation each validate a DPoP proof — and therefore
/// durably claim its `jti` in a globally bounded replay table — before any
/// client identity exists. That capacity is shared with every other route
/// that validates DPoP, so an unauthenticated caller allocating it is a
/// service-wide availability cost. This budget is the earliest boundary at
/// which the cost can be refused without reordering the claim behind an
/// attacker-controlled remote metadata fetch.
public struct OAuthPeerAdmissionPolicy: Sendable, Equatable {
    /// Requests one peer may make across PAR, token, and revocation in one
    /// window.
    ///
    /// This starts at the per-IP budget the deployment's CDN already applies
    /// to `/xrpc/*`, because the routes it covers are the ones that rule does
    /// not reach. The right number depends on how Catbird behaves when PAR
    /// answers 429 — a client that retries tightly makes a lower budget worse
    /// rather than better — so it is deliberately one named constant and one
    /// edit to change.
    public static let defaultAttempts = 600
    public static let defaultGlobalAttempts = 1_000
    public static let defaultWindow: TimeInterval = 10

    public let attempts: Int
    public let globalAttempts: Int
    public let window: TimeInterval
    public let maximumTrackedPeers: Int

    public init(
        attempts: Int = OAuthPeerAdmissionPolicy.defaultAttempts,
        globalAttempts: Int = OAuthPeerAdmissionPolicy.defaultGlobalAttempts,
        window: TimeInterval = OAuthPeerAdmissionPolicy.defaultWindow,
        maximumTrackedPeers: Int = 50_000
    ) throws {
        guard (1 ... 1_000_000).contains(attempts),
              (1 ... 1_000_000).contains(globalAttempts),
              window.isFinite,
              (1 ... 86_400).contains(window),
              (2 ... 1_000_000).contains(maximumTrackedPeers) else {
            throw AccountLoginAdmissionError.invalidConfiguration
        }
        self.attempts = attempts
        self.globalAttempts = globalAttempts
        self.window = window
        self.maximumTrackedPeers = maximumTrackedPeers
    }
}

/// Process-local fixed-window admission keyed on the request's client
/// address.
///
/// **This is deliberately process-local, and making it durable would be a
/// regression, not an upgrade.** It sits next to ``AccountLoginAdmissionService``,
/// which is durable, so the obvious reading is that this one is the lazy
/// version. It is not. Two reasons, in order of weight:
///
/// 1. The durable login table is globally capacity-bounded
///    (`maximumDurableEntries`, 100,000) and exhausting it fails *closed*
///    into ``AccountLoginAdmissionError/unavailable``. Putting unauthenticated
///    OAuth peers in that table would let anonymous traffic fill it and
///    thereby deny password **login** — one principal denying another through
///    a shared bucket, which is precisely the defect the handle-bucket sizing
///    above exists to fix. The fix for one finding would have recreated the
///    other.
/// 2. A restart resetting the window is not an evasion worth a schema change
///    on a live PDS. What this bounds is a *concurrent burst* from one peer
///    over a ten-second window, and restarting the server is not a primitive
///    an attacker can invoke — if they could, they would already have the
///    denial they were working toward.
///
/// Also note the storage boundary: nothing here crosses one, so addresses are
/// held as the already-validated literals rather than as HMAC digests. The
/// digesting in ``AccountLoginAdmissionService`` exists because handles and
/// addresses reach SQLite there, not as a general policy.
public actor OAuthPeerAdmissionService {
    private struct Bucket {
        var startedAt: Date
        var attempts: Int
    }

    /// Every request whose client address cannot be established shares one
    /// bucket, spelled so it cannot collide with an address literal.
    ///
    /// The alternative readings are both worse. Admitting an unidentifiable
    /// request removes the control exactly when a forwarding header is
    /// missing, which is the state an attacker would aim for. Rejecting it
    /// turns one proxy misconfiguration into total OAuth unavailability — a
    /// failure this deployment has already had once at the login route. A
    /// shared bounded bucket keeps the ceiling unconditional and degrades to
    /// a single global budget instead of an outage. This is the same
    /// reasoning as ``AccountLoginAdmissionService``'s invalid-handle
    /// sentinel.
    private static let unidentifiedPeer = "\u{0}unidentified"

    /// One budget for the whole process, shared across PAR, token, and
    /// revocation. Those three routes claim from one replay table, so
    /// splitting the budget per route would multiply what a peer can allocate
    /// from it.
    public static let shared = OAuthPeerAdmissionService()

    private let policy: OAuthPeerAdmissionPolicy
    private var globalBucket: Bucket?
    private var buckets: [String: Bucket] = [:]

    public init(policy: OAuthPeerAdmissionPolicy = try! .init()) {
        self.policy = policy
    }

    /// Charges one request against `peer`'s budget and the aggregate global budget.
    ///
    /// `peer` is the address the login client-identity policy resolved, or
    /// `nil` when it could not resolve one. Values that are not plausible
    /// address literals are treated as unresolved rather than as distinct
    /// keys, so a caller cannot inflate bucket cardinality.
    public func admit(
        peer: String?,
        now: Date = Date()
    ) -> OAuthPeerAdmissionDecision {
        // Check aggregate global budget without mutation.
        if let currentGlobal = globalBucket,
           now.timeIntervalSince(currentGlobal.startedAt) < policy.window {
            guard currentGlobal.attempts < policy.globalAttempts else {
                return .rateLimited
            }
        }

        // Check per-peer budget without mutation.
        let key = Self.bucketKey(for: peer)
        if let current = buckets[key] {
            // A backwards clock leaves the window open rather than starting a
            // fresh one; resetting on a negative age would be a free reset.
            if now.timeIntervalSince(current.startedAt) < policy.window {
                guard current.attempts < policy.attempts else {
                    return .rateLimited
                }
            }
        } else if buckets.count >= policy.maximumTrackedPeers {
            buckets = buckets.filter {
                now.timeIntervalSince($0.value.startedAt) < policy.window
            }
            guard buckets.count < policy.maximumTrackedPeers else {
                // A table still full of live windows is refused rather than
                // evicting a live attacker's bucket to make room.
                return .rateLimited
            }
        }

        // Both budgets admit: commit mutations to both.
        if let currentGlobal = globalBucket,
           now.timeIntervalSince(currentGlobal.startedAt) < policy.window {
            globalBucket = Bucket(
                startedAt: currentGlobal.startedAt,
                attempts: currentGlobal.attempts + 1
            )
        } else {
            globalBucket = Bucket(startedAt: now, attempts: 1)
        }

        if let current = buckets[key],
           now.timeIntervalSince(current.startedAt) < policy.window {
            buckets[key] = Bucket(
                startedAt: current.startedAt,
                attempts: current.attempts + 1
            )
        } else {
            buckets[key] = Bucket(startedAt: now, attempts: 1)
        }
        return .allowed
    }
    private static func bucketKey(for peer: String?) -> String {
        guard let peer else { return unidentifiedPeer }
        let bytes = Array(peer.utf8)
        guard (2 ... 45).contains(bytes.count),
              bytes.allSatisfy({ $0 >= 0x21 && $0 <= 0x7e }) else {
            return unidentifiedPeer
        }
        return peer
    }
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
        let trimmed = handle.trimmingCharacters(in: .whitespacesAndNewlines)
        let handleBytes = Array(trimmed.utf8)
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
        if let canonicalDID = try? AccountIdentifiers.validateDID(trimmed) {
            normalizedHandle = Data(canonicalDID.utf8)
        } else if let canonicalHandle = try? AccountIdentifiers.canonicalHandle(trimmed) {
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
