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

    /// A sequenced-event wakeup inside the 15-minute throttle does not
    /// re-announce.
    func testWakeupWithinUpdateThrottleDoesNotReAnnounce() async throws {
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
        defer { task.cancel() }
        try await waitUntil { await transport.snapshot().count == 1 }
        await hub.firehoseDidAppend(maxSeq: 1)
        try await Task.sleep(for: .seconds(1))
        let seen = await transport.snapshot()
        XCTAssertEqual(seen.count, 1)
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
