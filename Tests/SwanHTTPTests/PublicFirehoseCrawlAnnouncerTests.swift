import Foundation
import Logging
import SwanHTTP
import SwanSQLite
import XCTest

private actor RecordingCrawlTransport: PublicCrawlHTTPTransport {
    private var requests: [PublicCrawlAnnounceRequest] = []
    private var result = true

    func announce(_ request: PublicCrawlAnnounceRequest) async throws -> Bool {
        requests.append(request)
        return result
    }

    func snapshot() -> [PublicCrawlAnnounceRequest] {
        requests
    }

    func setResult(_ value: Bool) {
        result = value
    }
}

final class PublicFirehoseCrawlAnnouncerTests: XCTestCase {
    private let logger = Logger(label: "swan.public-firehose-crawl-announcer-tests")
    private let crawlerA = URL(string: "https://crawler-a.example")!
    private let crawlerB = URL(string: "https://crawler-b.example")!

    func testStartupAnnouncesEveryConfiguredCrawlerOnce() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await control.close() } }
        let hub = PublicFirehoseWakeupHub()
        let transport = RecordingCrawlTransport()
        let service = try SwanPublicFirehoseCrawlAnnouncerService(
            control: control, hub: hub, transport: transport,
            crawlers: [crawlerA, crawlerB], hostname: "swan.example", logger: logger
        )
        let task = Task { try await service.run() }
        defer { task.cancel() }
        try await waitUntil { await transport.snapshot().count == 2 }
        let seen = await transport.snapshot()
        XCTAssertEqual(Set(seen.map(\.origin)), [crawlerA, crawlerB])
        XCTAssertEqual(Set(seen.map(\.hostname)), ["swan.example"])
    }

    /// Failure schedules exponential backoff; state survives a service restart.
    func testFailureBackoffPersistsAcrossServiceRestart() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await control.close() } }
        let hub = PublicFirehoseWakeupHub()
        let transport = RecordingCrawlTransport()
        await transport.setResult(false)
        let first = try SwanPublicFirehoseCrawlAnnouncerService(
            control: control, hub: hub, transport: transport,
            crawlers: [crawlerA], hostname: "swan.example", logger: logger
        )
        let firstTask = Task { try await first.run() }
        try await waitUntil { await transport.snapshot().count == 1 }
        firstTask.cancel()
        try await waitUntil {
            let states = (try? await control.crawlAnnouncerStates()) ?? []
            return states.first?.attempts == 1 && states.first?.nextAttemptAt != nil
        }
        // A fresh service over the same database must respect next_attempt_at
        // (~30 s away) and not announce again immediately.
        let secondTransport = RecordingCrawlTransport()
        let second = try SwanPublicFirehoseCrawlAnnouncerService(
            control: control, hub: hub, transport: secondTransport,
            crawlers: [crawlerA], hostname: "swan.example", logger: logger
        )
        let secondTask = Task { try await second.run() }
        defer { secondTask.cancel() }
        try await Task.sleep(for: .seconds(1))
        let replayed = await secondTransport.snapshot()
        XCTAssertTrue(replayed.isEmpty)
    }

    /// A sequenced-event wakeup inside the update throttle does not
    /// re-announce, while a later wakeup (once the throttle has elapsed)
    /// does. The poll cadence equals the throttle (`min(throttle, 60 s)`),
    /// so a real recent `lastAttemptAt` would land the first consumed wakeup
    /// exactly on the throttle boundary; seeding it two seconds in the
    /// future gives the first pass a deterministically unelapsed throttle and
    /// the second pass an elapsed one.
    func testWakeupWithinUpdateThrottleDoesNotReAnnounce() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await control.close() } }
        let hub = PublicFirehoseWakeupHub()
        let transport = RecordingCrawlTransport()
        // Healthy state: the 24 h-style refresh is far in the future, so only
        // the sequenced branch could announce.
        let seededNow = Date().addingTimeInterval(2)
        try await control.recordCrawlAnnounceOutcome(
            origin: crawlerA.absoluteString,
            success: true,
            now: seededNow,
            nextAttemptAt: seededNow.addingTimeInterval(200)
        )
        let service = try SwanPublicFirehoseCrawlAnnouncerService(
            control: control, hub: hub, transport: transport,
            crawlers: [crawlerA], hostname: "swan.example",
            updateThrottle: .seconds(5),
            refreshInterval: .seconds(200),
            logger: logger
        )
        let task = Task { try await service.run() }
        defer { task.cancel() }
        try await Task.sleep(for: .milliseconds(300))
        let startupSeen = await transport.snapshot()
        XCTAssertTrue(
            startupSeen.isEmpty,
            "the non-sequenced startup pass must not announce while the refresh has not elapsed"
        )
        // Wakeup consumed by the first poll pass (~5 s): the throttle (5 s)
        // has not elapsed since the seeded attempt (~3 s ago at that point),
        // so the pass must stay silent.
        await hub.firehoseDidAppend(maxSeq: 1)
        try await Task.sleep(for: .seconds(6))
        let held = await transport.snapshot()
        XCTAssertEqual(held.count, 0, "a wakeup inside the update throttle must not re-announce")
        // A second wakeup, consumed after the throttle has elapsed, must
        // announce: the throttle gates only the window, not the branch.
        await hub.firehoseDidAppend(maxSeq: 2)
        try await waitUntil(timeoutNanoseconds: 15_000_000_000) {
            await transport.snapshot().count == 1
        }
        let seen = await transport.snapshot()
        XCTAssertEqual(seen.count, 1)
        XCTAssertEqual(seen.first?.hostname, "swan.example")
    }

    /// A sequenced-event wakeup after the update throttle has elapsed must
    /// re-announce even though the 24 h refresh (`next_attempt_at`) is still
    /// far in the future: the throttled-update branch is not gated by the
    /// refresh schedule.
    func testSequencedWakeupAfterUpdateThrottleElapsedReAnnounces() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await control.close() } }
        let hub = PublicFirehoseWakeupHub()
        let transport = RecordingCrawlTransport()
        // Healthy state with `last_attempt_at` ~6 s in the past and a future
        // refresh: the startup pass must stay silent and the sequenced pass
        // must announce on the throttle branch alone.
        let seededNow = Date().addingTimeInterval(-6)
        try await control.recordCrawlAnnounceOutcome(
            origin: crawlerA.absoluteString,
            success: true,
            now: seededNow,
            nextAttemptAt: seededNow.addingTimeInterval(200)
        )
        let service = try SwanPublicFirehoseCrawlAnnouncerService(
            control: control, hub: hub, transport: transport,
            crawlers: [crawlerA], hostname: "swan.example",
            updateThrottle: .seconds(5),
            refreshInterval: .seconds(200),
            logger: logger
        )
        let task = Task { try await service.run() }
        defer { task.cancel() }
        try await Task.sleep(for: .milliseconds(300))
        let startupSeen = await transport.snapshot()
        XCTAssertTrue(
            startupSeen.isEmpty,
            "the non-sequenced startup pass must not announce while the refresh has not elapsed"
        )
        await hub.firehoseDidAppend(maxSeq: 1)
        // The first poll pass (~5 s) consumes the wakeup with ~11 s elapsed
        // since the seeded attempt — past the 5 s throttle but ~3 min short
        // of the refresh.
        try await waitUntil(timeoutNanoseconds: 15_000_000_000) {
            await transport.snapshot().count == 1
        }
        let seen = await transport.snapshot()
        XCTAssertEqual(seen.count, 1)
        XCTAssertEqual(seen.first?.hostname, "swan.example")
    }

    /// Graceful shutdown must return cleanly instead of surfacing the
    /// cancellation thrown by the poll sleep.
    func testCancellationExitsCleanlyWithoutThrowing() async throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let control = try await SQLiteControlDatabase(dataDirectory: root)
        defer { Task { try? await control.close() } }
        let hub = PublicFirehoseWakeupHub()
        let transport = RecordingCrawlTransport()
        let service = try SwanPublicFirehoseCrawlAnnouncerService(
            control: control, hub: hub, transport: transport,
            crawlers: [crawlerA], hostname: "swan.example", logger: logger
        )
        let task = Task { try await service.run() }
        try await waitUntil { await transport.snapshot().count == 1 }
        task.cancel()
        do {
            try await task.value
        } catch {
            XCTFail("graceful cancellation must not propagate an error: \(error)")
        }
    }

    private func waitUntil(
        timeoutNanoseconds: UInt64 = 5_000_000_000,
        _ condition: @escaping @Sendable () async -> Bool
    ) async throws {
        let deadline = ContinuousClock.now + .seconds(
            Double(timeoutNanoseconds) / 1_000_000_000
        )
        while ContinuousClock.now < deadline {
            if await condition() { return }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("condition not met before deadline")
    }

    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanPublicFirehoseCrawlAnnouncerTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return root
    }
}
