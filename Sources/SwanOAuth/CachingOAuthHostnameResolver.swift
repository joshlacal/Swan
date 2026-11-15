import Foundation
import SwanCore

/// Coalesces and briefly caches hostname resolutions in front of another
/// resolver.
///
/// `OAuthBlockingDNSAdmission` bounds the process to four concurrent blocking
/// `getaddrinfo` calls and fails closed past that, which is correctly sized for
/// OAuth document and did:web fetches: a few lookups per sign-in. The XRPC
/// pipethrough has the opposite shape. A single AppView-backed screen in the
/// official client fires ten to twenty parallel requests, every one of them
/// resolving the same host, so the fifth onward were refused with
/// `unavailable` and surfaced to the client as a bare 502.
///
/// Two properties fix that without widening the admission bound:
///
/// - **Single flight.** Concurrent callers for one host await a single
///   in-flight lookup, so a cold burst of twenty requests takes one permit
///   rather than twenty.
/// - **Short TTL.** A hit costs no permit at all. The TTL is deliberately
///   small: pinning already assumes the resolved set is only trustworthy
///   briefly, and this bounds the DNS-rebinding window to that same interval.
///
/// This is not a policy relaxation. Callers still policy-check every literal
/// on every use, and failures are never cached — a lookup that threw is retried
/// by the next caller rather than being remembered as a refusal.
public actor CachingOAuthHostnameResolver: OAuthHostnameResolving {
    private struct Entry {
        let addresses: [OAuthIPAddress]
        let expiresAt: Date
    }

    private let upstream: any OAuthHostnameResolving
    private let ttl: TimeInterval
    private let maximumEntries: Int
    private let now: @Sendable () -> Date
    private var entries: [String: Entry] = [:]
    private var inFlight: [String: Task<[OAuthIPAddress], any Error>] = [:]

    public init(
        upstream: any OAuthHostnameResolving,
        ttl: TimeInterval = 30,
        maximumEntries: Int = 256,
        now: @Sendable @escaping () -> Date = { Date() }
    ) throws {
        guard ttl > 0, ttl <= 300, ttl.isFinite, (1 ... 4_096).contains(maximumEntries) else {
            throw SwanError.malformed("hostname resolution cache configuration is invalid")
        }
        self.upstream = upstream
        self.ttl = ttl
        self.maximumEntries = maximumEntries
        self.now = now
    }

    public func resolve(host: String) async throws -> [OAuthIPAddress] {
        let key = host.lowercased()
        let moment = now()
        if let entry = entries[key], entry.expiresAt > moment {
            return entry.addresses
        }
        entries.removeValue(forKey: key)
        if let existing = inFlight[key] {
            return try await existing.value
        }
        let upstream = upstream
        let task = Task<[OAuthIPAddress], any Error> {
            try await upstream.resolve(host: host)
        }
        inFlight[key] = task
        defer { inFlight.removeValue(forKey: key) }
        // A thrown lookup leaves no entry: a transient resolver outage must not
        // become a cached refusal for the whole TTL.
        let addresses = try await task.value
        store(host: key, addresses: addresses, at: now())
        return addresses
    }

    private func store(host: String, addresses: [OAuthIPAddress], at moment: Date) {
        entries[host] = Entry(addresses: addresses, expiresAt: moment.addingTimeInterval(ttl))
        guard entries.count > maximumEntries else { return }
        entries = entries.filter { $0.value.expiresAt > moment }
        guard entries.count > maximumEntries else { return }
        // Still over budget with nothing expired: drop the entries closest to
        // expiry, which are the ones a caller is least likely to reuse.
        let ordered = entries.sorted { $0.value.expiresAt < $1.value.expiresAt }
        for (host, _) in ordered.prefix(entries.count - maximumEntries) {
            entries.removeValue(forKey: host)
        }
    }
}
