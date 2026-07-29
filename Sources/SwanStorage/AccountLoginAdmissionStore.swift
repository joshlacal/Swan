import Foundation

/// The three independent abuse dimensions consumed by every password-login
/// attempt. Raw handles and socket addresses are deliberately not
/// representable at this storage boundary.
public enum AccountLoginRateLimitScope:
    String,
    CaseIterable,
    Hashable,
    Sendable
{
    case handle
    case directPeer = "direct-peer"
    case handlePeerPair = "handle-peer-pair"
}

public struct AccountLoginRateLimitBucket: Sendable, Equatable {
    public let scope: AccountLoginRateLimitScope
    public let keyDigest: Data
    public let maximumAttempts: Int
    public let window: TimeInterval

    public init(
        scope: AccountLoginRateLimitScope,
        keyDigest: Data,
        maximumAttempts: Int,
        window: TimeInterval
    ) throws {
        guard keyDigest.count == 32,
              (1 ... 10_000).contains(maximumAttempts),
              window.isFinite,
              (1 ... 86_400).contains(window) else {
            throw AccountControlStoreError.invalidInput
        }
        self.scope = scope
        self.keyDigest = keyDigest
        self.maximumAttempts = maximumAttempts
        self.window = window
    }
}

/// One atomic durable login-admission request. It always carries all three
/// dimensions so a caller cannot accidentally rate-limit only known accounts
/// or omit the direct socket peer.
public struct AccountLoginRateLimitRequest: Sendable, Equatable {
    public let buckets: [AccountLoginRateLimitBucket]
    public let maximumEntries: Int

    public init(
        buckets: [AccountLoginRateLimitBucket],
        maximumEntries: Int
    ) throws {
        let scopes = Set(buckets.map(\.scope))
        guard buckets.count == AccountLoginRateLimitScope.allCases.count,
              scopes == Set(AccountLoginRateLimitScope.allCases),
              (3 ... 1_000_000).contains(maximumEntries) else {
            throw AccountControlStoreError.invalidInput
        }
        self.buckets = buckets.sorted { $0.scope.rawValue < $1.scope.rawValue }
        self.maximumEntries = maximumEntries
    }
}

public enum AccountLoginRateLimitDecision: Sendable, Equatable {
    case allowed
    case limited
    /// No new digest is inserted after this result. Callers must fail closed
    /// rather than evicting a live attacker's bucket or persisting raw input.
    case capacityExhausted
}

public protocol AccountLoginAdmissionStore: Sendable {
    func consumeLoginRateLimit(
        _ request: AccountLoginRateLimitRequest,
        now: Date
    ) async throws -> AccountLoginRateLimitDecision
}
