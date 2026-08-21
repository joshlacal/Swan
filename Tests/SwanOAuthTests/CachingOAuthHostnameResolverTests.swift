import Foundation
import XCTest

@testable import SwanOAuth

/// The pipethrough regression this cache exists for: twenty parallel proxied
/// requests resolving one host exhausted the four-permit blocking DNS bound and
/// surfaced as 502s.
final class CachingOAuthHostnameResolverTests: XCTestCase {
    func testConcurrentCallersForOneHostShareASingleLookup() async throws {
        let upstream = CountingResolver(addresses: [try address("93.184.216.34")])
        let resolver = try CachingOAuthHostnameResolver(upstream: upstream)

        try await withThrowingTaskGroup(of: [OAuthIPAddress].self) { group in
            for _ in 0 ..< 20 {
                group.addTask { try await resolver.resolve(host: "api.example") }
            }
            var results = 0
            for try await addresses in group {
                XCTAssertEqual(addresses.map(\.description), ["93.184.216.34"])
                results += 1
            }
            XCTAssertEqual(results, 20)
        }
        // One permit for twenty callers. Before coalescing, the fifth onward
        // failed closed.
        let calls = await upstream.calls
        XCTAssertEqual(calls, 1)
    }

    func testAFreshEntryServesWithoutTouchingTheResolverUntilItExpires() async throws {
        let upstream = CountingResolver(addresses: [try address("93.184.216.34")])
        let clock = MutableClock()
        let resolver = try CachingOAuthHostnameResolver(
            upstream: upstream, ttl: 30, now: { clock.now }
        )

        _ = try await resolver.resolve(host: "api.example")
        _ = try await resolver.resolve(host: "api.example")
        let cachedCalls = await upstream.calls
        XCTAssertEqual(cachedCalls, 1)

        clock.advance(by: 31)
        _ = try await resolver.resolve(host: "api.example")
        let expiredCalls = await upstream.calls
        XCTAssertEqual(expiredCalls, 2, "an expired entry must be re-resolved")
    }

    func testAFailedLookupIsNeverCached() async throws {
        let upstream = CountingResolver(addresses: [try address("93.184.216.34")], failFirst: true)
        let resolver = try CachingOAuthHostnameResolver(upstream: upstream)

        do {
            _ = try await resolver.resolve(host: "api.example")
            XCTFail("expected the first lookup to fail")
        } catch {}
        // A transient resolver outage must not become a cached refusal.
        let addresses = try await resolver.resolve(host: "api.example")
        XCTAssertEqual(addresses.map(\.description), ["93.184.216.34"])
        let retriedCalls = await upstream.calls
        XCTAssertEqual(retriedCalls, 2)
    }

    func testDistinctHostsEachResolveOnce() async throws {
        let upstream = CountingResolver(addresses: [try address("93.184.216.34")])
        let resolver = try CachingOAuthHostnameResolver(upstream: upstream)
        _ = try await resolver.resolve(host: "api.example")
        _ = try await resolver.resolve(host: "chat.example")
        _ = try await resolver.resolve(host: "api.example")
        let hostCalls = await upstream.calls
        XCTAssertEqual(hostCalls, 2)
    }

    func testInvalidConfigurationIsRefused() throws {
        let upstream = CountingResolver(addresses: [])
        XCTAssertThrowsError(try CachingOAuthHostnameResolver(upstream: upstream, ttl: 0))
        XCTAssertThrowsError(try CachingOAuthHostnameResolver(upstream: upstream, ttl: 301))
        XCTAssertThrowsError(
            try CachingOAuthHostnameResolver(upstream: upstream, maximumEntries: 0))
    }

    private func address(_ literal: String) throws -> OAuthIPAddress {
        try XCTUnwrap(OAuthIPAddress(literal: literal))
    }
}

private actor CountingResolver: OAuthHostnameResolving {
    private(set) var calls = 0
    private let addresses: [OAuthIPAddress]
    private var failFirst: Bool

    init(addresses: [OAuthIPAddress], failFirst: Bool = false) {
        self.addresses = addresses
        self.failFirst = failFirst
    }

    func resolve(host: String) async throws -> [OAuthIPAddress] {
        calls += 1
        if failFirst {
            failFirst = false
            throw SwanOAuthTestResolverFailure.refused
        }
        // Long enough that the coalescing test's twenty callers genuinely
        // overlap on one lookup.
        try await Task.sleep(for: .milliseconds(20))
        return addresses
    }
}

private enum SwanOAuthTestResolverFailure: Error { case refused }

private final class MutableClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current = Date(timeIntervalSince1970: 1_700_000_000)

    var now: Date {
        lock.lock()
        defer { lock.unlock() }
        return current
    }

    func advance(by seconds: TimeInterval) {
        lock.lock()
        current = current.addingTimeInterval(seconds)
        lock.unlock()
    }
}
