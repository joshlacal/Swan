import Foundation
import NIOCore
import NIOPosix
import XCTest
@testable import SwanAccounts
import SwanStorage

final class MailpitSMTPDeliveryTests: XCTestCase {
    func testReplyDrivenDeliveryValidatesMultilineRepliesAndDotStuffsBody() async throws {
        try await withSMTPServer(mode: .accept) { delivery, server in
            try await delivery.deliver(
                to: try AccountEmailAddress("reader@example.test"),
                subject: "Swan proof",
                body: "first\n.leading-dot\nlast"
            )

            let transcript = server.transcript()
            XCTAssertEqual(transcript.commands, [
                "EHLO swan-lab",
                "MAIL FROM:<swan@example.test>",
                "RCPT TO:<reader@example.test>",
                "DATA",
                "QUIT",
            ])
            XCTAssertTrue(transcript.dataLines.contains("Subject: Swan proof"))
            XCTAssertTrue(transcript.dataLines.contains("..leading-dot"))
            XCTAssertFalse(transcript.dataLines.contains(".leading-dot"))
        }
    }

    func testRejectsMessageWhenServerDoesNotAcceptDATA() async throws {
        try await withSMTPServer(mode: .rejectFinal) { delivery, _ in
            await assertDeliveryError(.protocolViolation) {
                try await delivery.deliver(
                    to: try AccountEmailAddress("reader@example.test"),
                    subject: "Swan proof",
                    body: "proof"
                )
            }
        }
    }

    func testBoundsAdmissionAndTimesOutAStalledCommand() async throws {
        try await withSMTPServer(
            mode: .stallAfterEHLO,
            commandTimeout: 0.1,
            maximumConcurrentDeliveries: 1,
            maximumPendingDeliveries: 0
        ) { delivery, server in
            let first = Task {
                try await delivery.deliver(
                    to: try AccountEmailAddress("one@example.test"),
                    subject: "First",
                    body: "proof"
                )
            }
            try await server.waitUntilEHLO()

            await assertDeliveryError(.admissionFull) {
                try await delivery.deliver(
                    to: try AccountEmailAddress("two@example.test"),
                    subject: "Second",
                    body: "proof"
                )
            }
            await assertDeliveryError(.timedOut) {
                try await first.value
            }
        }
    }

    func testShutdownClosesActiveChannelBeforeWaitingForDeliveryDrain() async throws {
        try await withSMTPServer(
            mode: .stallAfterEHLO,
            commandTimeout: 30,
            maximumConcurrentDeliveries: 1,
            maximumPendingDeliveries: 0
        ) { delivery, server in
            let deliveryFinished = expectation(description: "delivery finished")
            let shutdownFinished = expectation(description: "shutdown finished")
            let deliveryTask = Task<Result<Void, Error>, Never> {
                defer { deliveryFinished.fulfill() }
                do {
                    try await delivery.deliver(
                        to: try AccountEmailAddress("reader@example.test"),
                        subject: "Swan proof",
                        body: "proof"
                    )
                    return .success(())
                } catch {
                    return .failure(error)
                }
            }
            try await server.waitUntilEHLO()
            let shutdownTask = Task<Result<Void, Error>, Never> {
                defer { shutdownFinished.fulfill() }
                do {
                    try await delivery.shutdown()
                    return .success(())
                } catch {
                    return .failure(error)
                }
            }

            let result = await XCTWaiter.fulfillment(
                of: [deliveryFinished, shutdownFinished],
                timeout: 0.5
            )
            if result != .completed {
                await server.closeActiveConnections()
            }
            XCTAssertEqual(result, .completed)
            switch await deliveryTask.value {
            case .success:
                XCTFail("stalled delivery unexpectedly succeeded")
            case let .failure(error):
                XCTAssertEqual(
                    error as? MailpitSMTPDeliveryError,
                    .unavailable
                )
            }
            switch await shutdownTask.value {
            case .success:
                break
            case let .failure(error):
                XCTFail("shutdown failed: \(error)")
            }
        }
    }

    func testBoundsRepliesAndRejectsUnsafeMessageFields() async throws {
        try await withSMTPServer(mode: .oversizedEHLOReply) {
            delivery,
            _ in
            await assertDeliveryError(.protocolViolation) {
                try await delivery.deliver(
                    to: try AccountEmailAddress("reader@example.test"),
                    subject: "Swan proof",
                    body: "proof"
                )
            }
        }

        let delivery = try MailpitSMTPDelivery(
            host: "127.0.0.1",
            port: 9,
            sender: try AccountEmailAddress("swan@example.test")
        )
        await assertDeliveryError(.invalidMessage) {
            try await delivery.deliver(
                to: try AccountEmailAddress("reader@example.test"),
                subject: "injected\r\nBcc: attacker@example.test",
                body: "proof"
            )
        }
        await assertDeliveryError(.invalidMessage) {
            try await delivery.deliver(
                to: try AccountEmailAddress("reader@example.test"),
                subject: "Swan proof",
                body: "bad\u{0}body"
            )
        }
        try await delivery.shutdown()
        try await delivery.shutdown()
        await assertDeliveryError(.shutDown) {
            try await delivery.deliver(
                to: try AccountEmailAddress("reader@example.test"),
                subject: "Swan proof",
                body: "proof"
            )
        }
    }

    func testRejectsNonLaboratoryDestinationsAtConstruction() throws {
        XCTAssertThrowsError(try MailpitSMTPDelivery(
            host: "smtp.example.com",
            sender: AccountEmailAddress("swan@example.test")
        )) {
            XCTAssertEqual(
                $0 as? MailpitSMTPDeliveryError,
                .invalidConfiguration
            )
        }
    }

    private func withSMTPServer(
        mode: LocalSMTPMode,
        commandTimeout: TimeInterval = 1,
        maximumConcurrentDeliveries: Int = 2,
        maximumPendingDeliveries: Int = 4,
        operation: (
            MailpitSMTPDelivery,
            LocalSMTPServer
        ) async throws -> Void
    ) async throws {
        let server = try await LocalSMTPServer.start(mode: mode)
        let delivery = try MailpitSMTPDelivery(
            host: "127.0.0.1",
            port: server.port,
            sender: try AccountEmailAddress("swan@example.test"),
            connectTimeout: 1,
            commandTimeout: commandTimeout,
            maximumConcurrentDeliveries: maximumConcurrentDeliveries,
            maximumPendingDeliveries: maximumPendingDeliveries
        )
        do {
            try await operation(delivery, server)
            try await delivery.shutdown()
            await server.close()
        } catch {
            try? await delivery.shutdown()
            await server.close()
            throw error
        }
    }

    private func assertDeliveryError<T>(
        _ expected: MailpitSMTPDeliveryError,
        operation: () async throws -> T,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await operation()
            XCTFail("expected \(expected)", file: file, line: line)
        } catch {
            XCTAssertEqual(
                error as? MailpitSMTPDeliveryError,
                expected,
                file: file,
                line: line
            )
        }
    }
}

private enum LocalSMTPMode: Sendable {
    case accept
    case rejectFinal
    case stallAfterEHLO
    case oversizedEHLOReply
}

private struct LocalSMTPTranscript: Sendable, Equatable {
    let commands: [String]
    let dataLines: [String]
}

/// Access is serialized by `lock`; promises are completed at most once.
private final class LocalSMTPReceipt: @unchecked Sendable {
    private let lock = NSLock()
    private let ehloPromise: EventLoopPromise<Void>
    private var commands: [String] = []
    private var dataLines: [String] = []
    private var didObserveEHLO = false
    private var activeConnections: [ObjectIdentifier: Channel] = [:]

    init(ehloPromise: EventLoopPromise<Void>) {
        self.ehloPromise = ehloPromise
    }

    func recordCommand(_ line: String) {
        lock.lock()
        commands.append(line)
        let shouldComplete = !didObserveEHLO && line.hasPrefix("EHLO ")
        if shouldComplete { didObserveEHLO = true }
        lock.unlock()
        if shouldComplete { ehloPromise.succeed(()) }
    }

    func recordData(_ line: String) {
        lock.lock()
        dataLines.append(line)
        lock.unlock()
    }

    func addConnection(_ channel: Channel) {
        lock.lock()
        activeConnections[ObjectIdentifier(channel)] = channel
        lock.unlock()
    }

    func removeConnection(_ channel: Channel) {
        lock.lock()
        activeConnections.removeValue(forKey: ObjectIdentifier(channel))
        lock.unlock()
    }

    func closeActiveConnections() async {
        let channels = lock.withLock { Array(activeConnections.values) }
        for channel in channels {
            try? await channel.close().get()
        }
    }

    func snapshot() -> LocalSMTPTranscript {
        lock.lock()
        defer { lock.unlock() }
        return .init(commands: commands, dataLines: dataLines)
    }

    func waitUntilEHLO() async throws {
        try await ehloPromise.futureResult.get()
    }

    func failIfPending() {
        lock.lock()
        let shouldFail = !didObserveEHLO
        if shouldFail { didObserveEHLO = true }
        lock.unlock()
        if shouldFail { ehloPromise.fail(CancellationError()) }
    }
}

private final class LocalSMTPServer: @unchecked Sendable {
    let port: Int
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private let receipt: LocalSMTPReceipt

    private init(
        port: Int,
        group: MultiThreadedEventLoopGroup,
        channel: Channel,
        receipt: LocalSMTPReceipt
    ) {
        self.port = port
        self.group = group
        self.channel = channel
        self.receipt = receipt
    }

    static func start(mode: LocalSMTPMode) async throws -> LocalSMTPServer {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        do {
            let receipt = LocalSMTPReceipt(
                ehloPromise: group.next().makePromise(of: Void.self)
            )
            let channel = try await ServerBootstrap(group: group)
                .serverChannelOption(
                    ChannelOptions.socketOption(.so_reuseaddr),
                    value: 1
                )
                .childChannelInitializer { channel in
                    channel.pipeline.addHandler(LocalSMTPHandler(
                        mode: mode,
                        receipt: receipt
                    ))
                }
                .bind(host: "127.0.0.1", port: 0)
                .get()
            guard let port = channel.localAddress?.port else {
                throw MailpitSMTPDeliveryError.unavailable
            }
            return .init(
                port: port,
                group: group,
                channel: channel,
                receipt: receipt
            )
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    func transcript() -> LocalSMTPTranscript {
        receipt.snapshot()
    }

    func waitUntilEHLO() async throws {
        try await receipt.waitUntilEHLO()
    }

    func closeActiveConnections() async {
        await receipt.closeActiveConnections()
    }

    func close() async {
        receipt.failIfPending()
        try? await channel.close().get()
        try? await group.shutdownGracefully()
    }
}

/// Test handler state is confined to its channel event loop.
private final class LocalSMTPHandler:
    ChannelInboundHandler,
    @unchecked Sendable
{
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let mode: LocalSMTPMode
    private let receipt: LocalSMTPReceipt
    private var inbound = ByteBuffer()
    private var receivingData = false

    init(mode: LocalSMTPMode, receipt: LocalSMTPReceipt) {
        self.mode = mode
        self.receipt = receipt
    }

    func channelActive(context: ChannelHandlerContext) {
        receipt.addConnection(context.channel)
        reply("220 mailpit ready\r\n", context: context)
    }

    func channelInactive(context: ChannelHandlerContext) {
        receipt.removeConnection(context.channel)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var bytes = unwrapInboundIn(data)
        inbound.writeBuffer(&bytes)
        while let lineFeed = inbound.readableBytesView.firstIndex(of: 0x0a) {
            let start = inbound.readerIndex
            guard lineFeed > start,
                  inbound.getInteger(
                      at: lineFeed - 1,
                      as: UInt8.self
                  ) == 0x0d else {
                context.close(promise: nil)
                return
            }
            let length = lineFeed - start - 1
            guard let bytes = inbound.readBytes(length: length),
                  inbound.readInteger(as: UInt8.self) == 0x0d,
                  inbound.readInteger(as: UInt8.self) == 0x0a else {
                context.close(promise: nil)
                return
            }
            process(
                String(decoding: bytes, as: UTF8.self),
                context: context
            )
        }
        inbound.discardReadBytes()
    }

    func errorCaught(
        context: ChannelHandlerContext,
        error _: any Error
    ) {
        context.close(promise: nil)
    }

    private func process(
        _ line: String,
        context: ChannelHandlerContext
    ) {
        if receivingData {
            if line == "." {
                receivingData = false
                switch mode {
                case .rejectFinal:
                    reply("550 rejected\r\n", context: context)
                default:
                    reply("250 queued\r\n", context: context)
                }
            } else {
                receipt.recordData(line)
            }
            return
        }

        receipt.recordCommand(line)
        if line.hasPrefix("EHLO ") {
            switch mode {
            case .stallAfterEHLO:
                break
            case .oversizedEHLOReply:
                reply(
                    "250-\(String(repeating: "A", count: 1_100))\r\n"
                        + "250 ok\r\n",
                    context: context
                )
            default:
                reply(
                    "250-mailpit\r\n"
                        + "250-PIPELINING\r\n"
                        + "250 8BITMIME\r\n",
                    context: context
                )
            }
        } else if line.hasPrefix("MAIL FROM:<") {
            reply("250 sender ok\r\n", context: context)
        } else if line.hasPrefix("RCPT TO:<") {
            reply("251 recipient forwarded\r\n", context: context)
        } else if line == "DATA" {
            receivingData = true
            reply("354 end with dot\r\n", context: context)
        } else if line == "QUIT" {
            reply("221 bye\r\n", context: context)
        } else {
            reply("500 invalid command\r\n", context: context)
        }
    }

    private func reply(
        _ value: String,
        context: ChannelHandlerContext
    ) {
        var buffer = context.channel.allocator.buffer(
            capacity: value.utf8.count
        )
        buffer.writeString(value)
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }
}
