import AsyncHTTPClient
import Foundation
import Logging
import NIOCore
import ServiceLifecycle
import SwanCore
import SwanPublicFirehose
import SwanSQLite

/// One outbound `com.atproto.sync.requestCrawl` announcement.
public struct PublicCrawlAnnounceRequest: Sendable, Equatable {
    public let origin: URL
    public let hostname: String

    public init(origin: URL, hostname: String) {
        self.origin = origin
        self.hostname = hostname
    }
}

public protocol PublicCrawlHTTPTransport: Sendable {
    /// POSTs com.atproto.sync.requestCrawl; returns true on a 2xx response.
    func announce(_ request: PublicCrawlAnnounceRequest) async throws -> Bool
}

/// The production transport, mirroring `AsyncHTTPClientPLCTransport`:
/// redirects are disallowed, connect and read timeouts are the bounded
/// maximum, and decompression is disabled so the status code is the only
/// decision input.
public final class AsyncHTTPClientPublicCrawlTransport: PublicCrawlHTTPTransport,
    @unchecked Sendable
{
    private let client: HTTPClient
    private let maximumTimeout: TimeInterval

    public init(maximumTimeout: TimeInterval = 10) throws {
        guard maximumTimeout > 0, maximumTimeout <= 30,
              maximumTimeout.isFinite else {
            throw SwanError.malformed("requestCrawl HTTP transport timeout is invalid")
        }
        self.maximumTimeout = maximumTimeout
        client = HTTPClient(configuration: .init(
            redirectConfiguration: .disallow,
            timeout: .init(
                connect: .milliseconds(Int64(maximumTimeout * 1_000)),
                read: .milliseconds(Int64(maximumTimeout * 1_000))
            ),
            decompression: .disabled
        ))
    }

    deinit {
        client.shutdown { _ in }
    }

    public func announce(_ request: PublicCrawlAnnounceRequest) async throws -> Bool {
        var outgoing = HTTPClientRequest(
            url: request.origin
                .appending(path: "xrpc/com.atproto.sync.requestCrawl")
                .absoluteString
        )
        outgoing.method = .POST
        outgoing.headers.add(name: "content-type", value: "application/json")
        let body = try JSONEncoder().encode(
            RequestCrawlBody(hostname: request.hostname)
        )
        outgoing.body = .bytes(ByteBuffer(bytes: body))
        let deadline = NIODeadline.now()
            + .milliseconds(Int64(maximumTimeout * 1_000))
        let response = try await client.execute(outgoing, deadline: deadline)
        return (200 ... 299).contains(Int(response.status.code))
    }
}

/// The requestCrawl payload; a one-field body keeps the wire format exact.
private struct RequestCrawlBody: Encodable {
    let hostname: String
}

/// A ServiceLifecycle peer of the retention pruner that POSTs
/// `com.atproto.sync.requestCrawl` to every configured crawler origin with
/// persistent per-crawler backoff in `control.sqlite`.
///
/// The run loop announces once on start, then wakes on either a fixed poll
/// interval (for the 24 h periodic refresh) or a sequenced-event hub wakeup
/// (for the throttled update announce). HTTP happens strictly outside every
/// store call; a transport failure never escapes `run()`, and the durable
/// backoff schedule survives a service or process restart.
public struct SwanPublicFirehoseCrawlAnnouncerService: Service {
    private let control: SQLiteControlDatabase
    private let hub: PublicFirehoseWakeupHub
    private let transport: any PublicCrawlHTTPTransport
    private let crawlers: [URL]
    private let hostname: String
    private let updateThrottle: Duration
    private let refreshInterval: Duration
    private let pollInterval: Duration
    private let logger: Logger

    public init(
        control: SQLiteControlDatabase,
        hub: PublicFirehoseWakeupHub,
        transport: any PublicCrawlHTTPTransport,
        crawlers: [URL],
        hostname: String,
        updateThrottle: Duration = .seconds(900),
        refreshInterval: Duration = .seconds(86_400),
        logger: Logger
    ) throws {
        guard !crawlers.isEmpty else {
            throw SwanError.malformed(
                "requestCrawl announcer requires at least one crawler origin"
            )
        }
        guard !hostname.isEmpty else {
            throw SwanError.malformed(
                "requestCrawl announcer hostname must not be empty"
            )
        }
        guard updateThrottle > .zero, refreshInterval > .zero else {
            throw SwanError.malformed(
                "requestCrawl announcer intervals must be positive"
            )
        }
        self.control = control
        self.hub = hub
        self.transport = transport
        self.crawlers = crawlers
        self.hostname = hostname
        self.updateThrottle = updateThrottle
        self.refreshInterval = refreshInterval
        pollInterval = min(updateThrottle, .seconds(60))
        self.logger = logger
    }

    public func run() async throws {
        let (stream, finish) = await hub.subscribeWithFinish()
        let signal = AnnounceSignal()
        let forwarder = Task {
            for await _ in stream {
                await signal.setDirty()
            }
        }
        defer {
            forwarder.cancel()
            finish()
        }
        await announcePass(now: Date(), sequenced: false)
        while !Task.isCancelled {
            try await Task.sleep(for: pollInterval)
            let sequenced = await signal.consumeDirty()
            await announcePass(now: Date(), sequenced: sequenced)
        }
    }

    private func announcePass(now: Date, sequenced: Bool) async {
        let states: [PublicCrawlAnnouncerState]
        do {
            states = try await control.crawlAnnouncerStates()
        } catch {
            logger.error("requestCrawl announcer state read failed", metadata: [
                "error": "\(error)",
            ])
            return
        }
        let nowMicros: Int64
        do {
            nowMicros = try PublicFirehoseTime.microseconds(now)
        } catch {
            logger.error("requestCrawl announcer clock is out of range")
            return
        }
        let stateByOrigin = Dictionary(
            uniqueKeysWithValues: states.map { ($0.crawlerOrigin, $0) }
        )
        for crawler in crawlers {
            let origin = crawler.absoluteString
            let state = stateByOrigin[origin]
            guard isEligible(
                state: state,
                nowMicros: nowMicros,
                sequenced: sequenced
            ) else {
                continue
            }
            let request = PublicCrawlAnnounceRequest(
                origin: crawler,
                hostname: hostname
            )
            let transportError: String?
            let succeeded: Bool
            do {
                succeeded = try await transport.announce(request)
                transportError = nil
            } catch {
                succeeded = false
                transportError = "\(error)"
            }
            if succeeded {
                await recordOutcome(
                    origin: origin,
                    success: true,
                    now: now,
                    nextAttemptAt: now.addingTimeInterval(
                        refreshIntervalSeconds
                    ),
                    attemptsAfter: 0,
                    backoffSeconds: nil,
                    transportError: nil
                )
            } else {
                let backoff = backoffAfterFailure(attempts: state?.attempts ?? 0)
                await recordOutcome(
                    origin: origin,
                    success: false,
                    now: now,
                    nextAttemptAt: now.addingTimeInterval(backoff),
                    attemptsAfter: (state?.attempts ?? 0) + 1,
                    backoffSeconds: backoff,
                    transportError: transportError
                )
            }
        }
    }

    private func recordOutcome(
        origin: String,
        success: Bool,
        now: Date,
        nextAttemptAt: Date,
        attemptsAfter: Int64,
        backoffSeconds: TimeInterval?,
        transportError: String?
    ) async {
        do {
            try await control.recordCrawlAnnounceOutcome(
                origin: origin,
                success: success,
                now: now,
                nextAttemptAt: nextAttemptAt
            )
        } catch {
            logger.error("requestCrawl announce outcome record failed", metadata: [
                "origin": .string(origin),
                "error": .string("\(error)"),
            ])
            return
        }
        if success {
            logger.debug("requestCrawl announced", metadata: [
                "origin": .string(origin),
            ])
        } else {
            var metadata: Logger.Metadata = [
                "origin": .string(origin),
                "attempts": .string("\(attemptsAfter)"),
                "backoffSeconds": .string(
                    backoffSeconds.map { String(format: "%.1f", $0) } ?? "nil"
                ),
            ]
            if let transportError {
                metadata["error"] = .string(transportError)
            }
            logger.warning("requestCrawl announce failed", metadata: metadata)
        }
    }

    /// The exact eligibility rule: a never-attempted crawler is always
    /// eligible; a crawler in failure backoff only when its schedule has
    /// passed; a healthy crawler on the 24 h refresh or, for sequenced
    /// passes, when the update throttle has elapsed.
    private func isEligible(
        state: PublicCrawlAnnouncerState?,
        nowMicros: Int64,
        sequenced: Bool
    ) -> Bool {
        guard let state, let nextAttemptAt = state.nextAttemptAt else {
            return true
        }
        guard nowMicros >= nextAttemptAt else { return false }
        if state.attempts > 0 { return true }
        if sequenced {
            guard let lastAttemptAt = state.lastAttemptAt else { return true }
            return nowMicros - lastAttemptAt >= updateThrottleMicroseconds
        }
        return false
    }

    /// `min(3600 s, 30 s × 2^min(attempts, 7))` with ±20% jitter.
    private func backoffAfterFailure(attempts: Int64) -> TimeInterval {
        let exponentialSeconds = 30 * pow(2, Double(min(attempts, 7)))
        let cappedSeconds = min(3_600, exponentialSeconds)
        return cappedSeconds * Double.random(in: 0.8 ... 1.2)
    }

    private var refreshIntervalSeconds: TimeInterval {
        let components = refreshInterval.components
        return TimeInterval(components.seconds)
            + TimeInterval(components.attoseconds) / 1e18
    }

    private var updateThrottleMicroseconds: Int64 {
        let components = updateThrottle.components
        let seconds = components.seconds.multipliedReportingOverflow(by: 1_000_000)
        let fraction = components.attoseconds / 1_000_000_000_000
        let micros = seconds.partialValue.addingReportingOverflow(fraction)
        return micros.partialValue
    }
}

/// Actor-held flag flipped by the hub forwarder and consumed by the run loop,
/// so the AsyncStream iterator never crosses a child-task boundary.
private actor AnnounceSignal {
    private var dirty = false

    func setDirty() {
        dirty = true
    }

    func consumeDirty() -> Bool {
        let wasDirty = dirty
        dirty = false
        return wasDirty
    }
}
