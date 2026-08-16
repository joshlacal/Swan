import Foundation

public enum OperationalMetric: String, CaseIterable, Sendable, Hashable {
    case httpError = "http_error"
    case auth = "auth"
    case signup = "signup"
    case email = "email"
    case identityRevalidation = "identity_revalidation"
    case outbox = "outbox"
    case firehose = "firehose"
    case backup = "backup"
}

public enum OperationalMetricError: Error, Sendable, Equatable {
    case forbiddenLabel
    case invalidLabel
}

/// In-process counters with a strict label allow-list. Values are aggregate
/// operational facts only; identifiers, credentials, paths, and payloads are
/// deliberately rejected at the metric boundary.
public final class OperationalMetrics: @unchecked Sendable {
    /// Local accumulator only; runtime registration must inject a real sink.
    public let assembled = false
    private let lock = NSLock()
    private var counts: [OperationalMetric: Int] = [:]

    public init() {}

    public func increment(_ metric: OperationalMetric, labels: [String: String] = [:]) throws {
        let allowed: Set<String> = ["status", "result", "kind", "reason"]
        guard labels.keys.allSatisfy({ allowed.contains($0) }) else { throw OperationalMetricError.forbiddenLabel }
        guard labels.values.allSatisfy({ value in
            !value.isEmpty && value.utf8.count <= 32 && value.utf8.allSatisfy {
                ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || $0 == 45 || $0 == 95
            }
        }) else { throw OperationalMetricError.invalidLabel }
        lock.lock(); defer { lock.unlock() }
        counts[metric, default: 0] += 1
    }

    public func snapshot() -> [OperationalMetric: Int] {
        lock.lock(); defer { lock.unlock() }
        return counts
    }
}

public enum OperationalReadinessCheck: String, CaseIterable, Sendable {
    case http
    case auth
    case signup
    case email
    case identity
    case outbox
    case firehose
    case backup
}

public struct OperationalReadinessReport: Sendable, Equatable {
    public let assembled: Bool
    public let ready: Bool
    public let checks: [OperationalReadinessCheck: Bool]
    public let missing: [OperationalReadinessCheck]

    public init(assembled: Bool, ready: Bool, checks: [OperationalReadinessCheck: Bool], missing: [OperationalReadinessCheck]) {
        self.assembled = assembled
        self.ready = ready
        self.checks = checks
        self.missing = missing
    }
}

public final class OperationalReadiness: @unchecked Sendable {
    public let assembled = false
    private let lock = NSLock()
    private var checks: [OperationalReadinessCheck: Bool] = [:]

    public init() {}

    public func set(_ check: OperationalReadinessCheck, healthy: Bool) {
        lock.lock(); defer { lock.unlock() }
        checks[check] = healthy
    }

    public func report() -> OperationalReadinessReport {
        lock.lock(); defer { lock.unlock() }
        let missing = OperationalReadinessCheck.allCases.filter { checks[$0] != true }
        return .init(assembled: assembled, ready: assembled && missing.isEmpty, checks: checks, missing: missing)
    }
}
