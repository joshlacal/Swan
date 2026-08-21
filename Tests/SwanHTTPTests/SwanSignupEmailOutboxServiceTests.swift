import Foundation
@testable import SwanAccounts
@testable import SwanHTTP
import SwanSQLite
import SwanStorage
import XCTest

final class SwanSignupEmailOutboxServiceTests: XCTestCase {
    func testCancellationStopsPollingAndShutsDownSMTPExactlyOnce() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanSignupEmailOutboxServiceTests-\(UUID().uuidString)")
        let database = try await SQLiteControlDatabase(dataDirectory: root)
        defer {
            Task {
                try? await database.close()
                try? FileManager.default.removeItem(at: root)
            }
        }

        let probe = SMTPShutdownProbe()
        let transport = ProbeSMTPTransport(probe: probe)
        let configuration = try AuthenticatedSMTPConfiguration(
            host: "smtp.example.com",
            port: 587,
            mode: .startTLS,
            username: "user",
            password: "password",
            mechanism: .plain,
            expectedHostname: "smtp.example.com"
        )
        let delivery = try AuthenticatedSMTPDelivery(
            configuration: configuration,
            transport: transport,
            attemptTimeout: .milliseconds(100)
        )
        let worker = SignupEmailOutboxWorker(store: database) { _ in }
        let service = SwanSignupEmailOutboxService(
            worker: worker,
            delivery: delivery,
            idlePollInterval: .seconds(60)
        )

        let running = Task { try await service.run() }
        try await Task.sleep(for: .milliseconds(100))
        running.cancel()
        try await running.value

        // The lifecycle owner performs one shutdown on cancellation. A
        // caller-side duplicate is harmless because the NIO transport's
        // shutdown gate is idempotent as well.
        try await delivery.shutdown()
        let shutdownCount = await probe.count()
        XCTAssertEqual(shutdownCount, 1)
    }

    func testConcurrentShutdownSharesFailureAndAllowsAConfirmedRetry() async throws {
        let probe = SMTPShutdownProbe(failFirstShutdown: true)
        let transport = ControlledSMTPTransport(probe: probe)
        let configuration = try AuthenticatedSMTPConfiguration(
            host: "smtp.example.com",
            port: 587,
            mode: .startTLS,
            username: "user",
            password: "password",
            mechanism: .plain,
            expectedHostname: "smtp.example.com",
            maximumAttempts: 1
        )
        let delivery = try AuthenticatedSMTPDelivery(
            configuration: configuration,
            transport: transport,
            attemptTimeout: .milliseconds(100)
        )

        let first = Task { () -> String in
            do {
                try await delivery.shutdown()
                return "success"
            } catch {
                return String(describing: error)
            }
        }
        await probe.waitForShutdownCall()
        let second = Task { () -> String in
            do {
                try await delivery.shutdown()
                return "success"
            } catch {
                return String(describing: error)
            }
        }
        let firstResult = await first.value
        let secondResult = await second.value
        let firstShutdownCount = await probe.shutdownCount()
        XCTAssertNotEqual(firstResult, "success")
        XCTAssertNotEqual(secondResult, "success")
        XCTAssertEqual(firstShutdownCount, 1)

        // A failed teardown remains fenced for delivery but is retry-safe. A
        // later caller gets a fresh attempt rather than inheriting a stale
        // failed task forever.
        try await delivery.shutdown()
        let retryShutdownCount = await probe.shutdownCount()
        XCTAssertEqual(retryShutdownCount, 2)
        do {
            try await delivery.deliver(
                to: try AccountEmailAddress("alice@example.com"),
                subject: "after shutdown",
                body: "body",
                idempotencyKey: "shutdown-fence"
            )
            XCTFail("delivery after shutdown start must fail closed")
        } catch let error as MailpitSMTPDeliveryError {
            XCTAssertEqual(error, .shutDown)
        }
    }

    func testLateWaitersCannotClearAReplacedShutdownGeneration() async throws {
        let probe = SMTPShutdownProbe(failFirstShutdown: true)
        let transport = ProbeSMTPTransport(probe: probe)
        let configuration = try AuthenticatedSMTPConfiguration(
            host: "smtp.example.com",
            port: 587,
            mode: .startTLS,
            username: "user",
            password: "password",
            mechanism: .plain,
            expectedHostname: "smtp.example.com",
            maximumAttempts: 1
        )
        let delivery = try AuthenticatedSMTPDelivery(
            configuration: configuration,
            transport: transport,
            attemptTimeout: .milliseconds(100)
        )

        let first = Task { () -> Result<Void, Error> in
            do { try await delivery.shutdown(); return .success(()) }
            catch { return .failure(error) }
        }
        await probe.waitForShutdownCount(1)
        let lateA = Task { () -> Result<Void, Error> in
            do { try await delivery.shutdown(); return .success(()) }
            catch { return .failure(error) }
        }
        let lateB = Task { () -> Result<Void, Error> in
            do { try await delivery.shutdown(); return .success(()) }
            catch { return .failure(error) }
        }

        // The first transport call fails after all three callers are waiting.
        // The first caller may immediately install generation 2; late
        // generation-1 waiters must not erase it when they resume.
        let firstResult = await first.value
        XCTAssertTrue({ if case .failure = firstResult { return true }; return false }())
        let retry = Task { () -> Result<Void, Error> in
            do { try await delivery.shutdown(); return .success(()) }
            catch { return .failure(error) }
        }
        await probe.waitForShutdownCount(2)
        _ = await retry.value
        _ = await lateA.value
        _ = await lateB.value
        let shutdownCount = await probe.shutdownCount()
        XCTAssertEqual(shutdownCount, 2)
    }

    func testShutdownWaitsForInFlightDeliveryBeforeClosingTransport() async throws {
        let probe = SMTPShutdownProbe(failFirstShutdown: false)
        let transport = ControlledSMTPTransport(probe: probe)
        let configuration = try AuthenticatedSMTPConfiguration(
            host: "smtp.example.com",
            port: 587,
            mode: .startTLS,
            username: "user",
            password: "password",
            mechanism: .plain,
            expectedHostname: "smtp.example.com",
            maximumAttempts: 1
        )
        let delivery = try AuthenticatedSMTPDelivery(
            configuration: configuration,
            transport: transport,
            attemptTimeout: .milliseconds(500)
        )

        let inFlight = Task {
            try await delivery.deliver(
                to: try AccountEmailAddress("alice@example.com"),
                subject: "in flight",
                body: "body",
                idempotencyKey: "in-flight"
            )
        }
        await probe.waitForDeliveryStart()
        let shutdown = Task { try await delivery.shutdown() }
        try await Task.sleep(for: .milliseconds(20))
        let shutdownBeforeRelease = await probe.shutdownStarted()
        XCTAssertFalse(shutdownBeforeRelease)
        await probe.releaseDelivery()
        try await inFlight.value
        try await shutdown.value
        let shutdownAfterRelease = await probe.shutdownStarted()
        let finalShutdownCount = await probe.shutdownCount()
        XCTAssertTrue(shutdownAfterRelease)
        XCTAssertEqual(finalShutdownCount, 1)
    }
}

private actor SMTPShutdownProbe {
    private var shutdowns = 0
    private var deliveryStarted = false
    private var released = false
    private var failFirstShutdown: Bool
    init(failFirstShutdown: Bool = false) { self.failFirstShutdown = failFirstShutdown }
    func recordShutdown() async throws {
        shutdowns += 1
        if failFirstShutdown {
            failFirstShutdown = false
            try? await Task.sleep(for: .milliseconds(50))
            throw MailpitSMTPDeliveryError.unavailable
        }
    }
    func recordDeliveryStart() { deliveryStarted = true }
    func releaseDelivery() { released = true }
    func waitForDeliveryStart() async {
        while !deliveryStarted { try? await Task.sleep(for: .milliseconds(1)) }
    }
    func waitForShutdownCall() async {
        while shutdowns == 0 { try? await Task.sleep(for: .milliseconds(1)) }
    }
    func waitForShutdownCount(_ expected: Int) async {
        while shutdowns < expected { try? await Task.sleep(for: .milliseconds(1)) }
    }
    func isReleased() -> Bool { released }
    func shutdownStarted() -> Bool { shutdowns > 0 }
    func count() -> Int { shutdowns }
    func shutdownCount() -> Int { shutdowns }
}

private struct ProbeSMTPTransport: AuthenticatedSMTPDeadlineTransport, AuthenticatedSMTPTransportShutdown {
    let probe: SMTPShutdownProbe

    func deliver(
        configuration _: AuthenticatedSMTPConfiguration,
        to _: AccountEmailAddress,
        subject _: String,
        body _: String,
        idempotencyKey _: String
    ) async throws {}

    func deliver(
        configuration _: AuthenticatedSMTPConfiguration,
        to _: AccountEmailAddress,
        subject _: String,
        body _: String,
        idempotencyKey _: String,
        deadline _: ContinuousClock.Instant
    ) async throws {}

    func shutdown() async throws {
        try await probe.recordShutdown()
    }
}

private struct ControlledSMTPTransport: AuthenticatedSMTPDeadlineTransport, AuthenticatedSMTPTransportShutdown {
    let probe: SMTPShutdownProbe

    func deliver(
        configuration _: AuthenticatedSMTPConfiguration,
        to _: AccountEmailAddress,
        subject _: String,
        body _: String,
        idempotencyKey _: String
    ) async throws {}

    func deliver(
        configuration _: AuthenticatedSMTPConfiguration,
        to _: AccountEmailAddress,
        subject _: String,
        body _: String,
        idempotencyKey _: String,
        deadline _: ContinuousClock.Instant
    ) async throws {
        await probe.recordDeliveryStart()
        while !(await probe.isReleased()) {
            try await Task.sleep(for: .milliseconds(1))
        }
    }

    func shutdown() async throws {
        try await probe.recordShutdown()
    }
}
