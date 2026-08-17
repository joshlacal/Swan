import Crypto
import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import SwanCore
import SwanStorage

/// Production NIO transport for `AuthenticatedSMTPNetworkTransport`.
///
/// `NIOAuthenticatedSMTPTransport` owns the shared NIO event-loop group and
/// TLS context; `NIOAuthenticatedSMTPTLSConnection` is one SMTP session
/// (one channel) implementing the `SMTPTLSConnectionWithDeadline` seam.
/// Certificate hostname validation is performed by NIOSSL against the
/// configured expected hostname; the transport adapter independently checks
/// `authenticatedHostname` before permitting AUTH.
public struct NIOAuthenticatedSMTPTransport: Sendable {
    private let group: MultiThreadedEventLoopGroup
    private let tlsContext: NIOSSLContext

    public init(group: MultiThreadedEventLoopGroup? = nil, additionalTrustRootsPEM: Data? = nil) throws {
        var tls = TLSConfiguration.makeClientConfiguration()
        if let pem = additionalTrustRootsPEM {
            tls.trustRoots = .certificates(try NIOSSLCertificate.fromPEMBytes([UInt8](pem)))
        }
        tlsContext = try NIOSSLContext(configuration: tls)
        self.group = group ?? MultiThreadedEventLoopGroup(numberOfThreads: 2)
    }

    /// The connect factory consumed by `AuthenticatedSMTPNetworkTransport`.
    /// The transport's own group is captured so the connection and the group
    /// cannot drift apart; the caller must not close the group separately.
    public func connect(
        configuration: AuthenticatedSMTPConfiguration,
        deadline: ContinuousClock.Instant
    ) async throws -> any SMTPTLSConnectionWithDeadline {
        try await NIOAuthenticatedSMTPTLSConnection.connect(
            configuration: configuration,
            group: group,
            tlsContext: tlsContext,
            deadline: deadline
        )
    }

    public func makeTransport() -> AuthenticatedSMTPNetworkTransport {
        AuthenticatedSMTPNetworkTransport { configuration, deadline in
            try await self.connect(configuration: configuration, deadline: deadline)
        }
    }
}

/// One deadline-bounded SMTP session. The channel is created and the SMTP
/// greeting/EHLO/(START)TLS handshake complete inside `connect`; after that
/// the session serves `authenticate` and `send` calls. A deadline is applied
/// per call: the channel is closed at the deadline, which is the transport
/// contract rather than a cooperative timeout.
public struct NIOAuthenticatedSMTPTLSConnection: SMTPTLSConnectionWithDeadline {
    private let channel: Channel
    private let handler: NIOAuthenticatedSMTPClientHandler
    public let authenticatedHostname: String

    private init(channel: Channel, handler: NIOAuthenticatedSMTPClientHandler, hostname: String) {
        self.channel = channel
        self.handler = handler
        authenticatedHostname = hostname
    }

    static func connect(
        configuration: AuthenticatedSMTPConfiguration,
        group: MultiThreadedEventLoopGroup,
        tlsContext: NIOSSLContext,
        deadline: ContinuousClock.Instant
    ) async throws -> NIOAuthenticatedSMTPTLSConnection {
        guard configuration.mode != .plaintextLab,
              let expected = configuration.expectedHostname,
              !expected.isEmpty else {
            throw MailpitSMTPDeliveryError.invalidConfiguration
        }
        let handler = NIOAuthenticatedSMTPClientHandler(
            configuration: configuration,
            tlsContext: tlsContext
        )
        let bootstrap = ClientBootstrap(group: group)
            .connectTimeout(.milliseconds(10_000))
            .channelOption(
                ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY),
                value: 1
            )
            .channelInitializer { channel in
                let pipeline = channel.pipeline
                if configuration.mode == .implicitTLS {
                    do {
                        let tlsHandler = try NIOSSLClientHandler(
                            context: tlsContext,
                            serverHostname: expected
                        )
                        return pipeline.addHandler(tlsHandler).flatMap {
                            pipeline.addHandler(handler)
                        }
                    } catch {
                        return channel.eventLoop.makeFailedFuture(error)
                    }
                }
                return pipeline.addHandler(handler)
            }
        let channel: Channel
        do {
            channel = try await bootstrap.connect(host: configuration.host, port: configuration.port).get()
        } catch ChannelError.connectTimeout(_) {
            throw MailpitSMTPDeliveryError.timedOut
        } catch {
            throw MailpitSMTPDeliveryError.unavailable
        }
        let connection = NIOAuthenticatedSMTPTLSConnection(
            channel: channel,
            handler: handler,
            hostname: expected.lowercased()
        )
        do {
            try await handler.readyFuture.get()
        } catch {
            try? await channel.close().get()
            throw error
        }
        // A deadline observed at connect time applies to the whole session.
        try await connection.applyDeadline(deadline)
        return connection
    }

    public func authenticate(
        username: String,
        password: String,
        mechanism: SMTPAuthMechanism
    ) async throws {
        try await authenticate(
            username: username,
            password: password,
            mechanism: mechanism,
            deadline: .now.advanced(by: .seconds(30))
        )
    }

    public func authenticate(
        username: String,
        password: String,
        mechanism: SMTPAuthMechanism,
        deadline: ContinuousClock.Instant
    ) async throws {
        try await withTaskCancellationHandler {
            try await handler.enqueue(.authenticate(username: username, password: password, mechanism: mechanism)).get()
        } onCancel: {
            channel.close(promise: nil)
        }
        try await applyDeadline(deadline)
    }

    public func send(
        to: AccountEmailAddress,
        subject: String,
        body: String,
        idempotencyKey: String
    ) async throws {
        try await send(to: to, subject: subject, body: body, idempotencyKey: idempotencyKey, deadline: .now.advanced(by: .seconds(30)))
    }

    public func send(
        to: AccountEmailAddress,
        subject: String,
        body: String,
        idempotencyKey: String,
        deadline: ContinuousClock.Instant
    ) async throws {
        guard Self.safeHeader(subject), Self.safeBody(body) else {
            throw MailpitSMTPDeliveryError.invalidMessage
        }
        try await withTaskCancellationHandler {
            try await handler.enqueue(.send(to: to.value, subject: subject, dotStuffedBody: Self.dotStuff(body))).get()
        } onCancel: {
            channel.close(promise: nil)
        }
        try await applyDeadline(deadline)
    }

    private func applyDeadline(_ deadline: ContinuousClock.Instant) async throws {
        let now = ContinuousClock.now
        guard deadline > now else {
            channel.close(promise: nil)
            throw MailpitSMTPDeliveryError.timedOut
        }
        let duration = now.duration(to: deadline)
        let seconds = duration.components.seconds
        let attoseconds = duration.components.attoseconds
        guard seconds >= 0, attoseconds >= 0 else {
            channel.close(promise: nil)
            throw MailpitSMTPDeliveryError.timedOut
        }
        let nanoseconds = seconds * 1_000_000_000 + attoseconds / 1_000_000_000
        guard nanoseconds <= Int64.max else {
            channel.close(promise: nil)
            throw MailpitSMTPDeliveryError.timedOut
        }
        try await channel.eventLoop.scheduleTask(in: .nanoseconds(nanoseconds)) {
            self.channel.close(promise: nil)
        }.futureResult.get()
    }

    private static func safeHeader(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        return !bytes.isEmpty && bytes.count <= 160
            && bytes.allSatisfy { (0x20 ... 0x7e).contains($0) }
    }

    private static func safeBody(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty, bytes.count <= 4_096,
              bytes.allSatisfy({
                  $0 == 0x09 || $0 == 0x0a || (0x20 ... 0x7e).contains($0)
              }) else { return false }
        return value.split(separator: "\n", omittingEmptySubsequences: false).allSatisfy { line in
            line.utf8.count <= (line.first == "." ? 997 : 998)
        }
    }

    private static func dotStuff(_ value: String) -> String {
        value.split(separator: "\n", omittingEmptySubsequences: false).map { line in
            line.first == "." ? ".\(line)" : String(line)
        }.joined(separator: "\r\n")
    }
}

private enum NIOAuthenticatedSMTPOperation: Sendable {
    case authenticate(username: String, password: String, mechanism: SMTPAuthMechanism)
    case send(to: String, subject: String, dotStuffedBody: String)
}

/// Reply-driven SMTP session handler. NIO invokes it exclusively on one
/// channel event loop; all parser state is confined to that loop and only
/// completion promises cross back to Swift concurrency.
private final class NIOAuthenticatedSMTPClientHandler:
    ChannelInboundHandler,
    @unchecked Sendable
{
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private enum Phase {
        case greeting
        case ehlo
        case startTLS
        case tlsHandshake
        case ehloAfterTLS
        case auth
        case mail
        case recipient
        case data
        case acceptance
        case quit
        case finished
    }

    private enum AuthStep {
        case none
        case loginUsername
        case loginPassword
    }

    private static let maximumReplyLineBytes = 1_000
    private static let maximumReplyLines = 64
    private static let maximumReplyBytes = 32 * 1_024
    private static let maximumLinesPerReply = 32
    private static let maximumBytesPerReply = 8 * 1_024

    private let configuration: AuthenticatedSMTPConfiguration
    private let tlsContext: NIOSSLContext
    private var readyPromise: EventLoopPromise<Void>?
    private var context: ChannelHandlerContext?

    private var phase = Phase.greeting
    private var authStep = AuthStep.none
    private var pending: (operation: NIOAuthenticatedSMTPOperation, promise: EventLoopPromise<Void>)?
    private var pendingQueue: [(operation: NIOAuthenticatedSMTPOperation, promise: EventLoopPromise<Void>)] = []
    private var inbound = ByteBuffer()
    private var totalReplyLines = 0
    private var totalReplyBytes = 0
    private var currentReplyLines = 0
    private var currentReplyBytes = 0
    private var multilineCode: Int?
    private var completed = false

    init(configuration: AuthenticatedSMTPConfiguration, tlsContext: NIOSSLContext) {
        self.configuration = configuration
        self.tlsContext = tlsContext
    }

    var readyFuture: EventLoopFuture<Void> {
        // `connect` calls this only after the channel initializer ran, so
        // `handlerAdded` has already created the promise on the channel's
        // event loop.
        readyPromise!.futureResult
    }

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
        readyPromise = context.eventLoop.makePromise(of: Void.self)
    }

    func channelActive(context: ChannelHandlerContext) {
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var bytes = unwrapInboundIn(data)
        totalReplyBytes += bytes.readableBytes
        guard totalReplyBytes <= Self.maximumReplyBytes else {
            fail(.protocolViolation)
            return
        }
        inbound.writeBuffer(&bytes)
        parseLines(context)
    }

    func channelInactive(context _: ChannelHandlerContext) {
        if !completed {
            completeAll(.unavailable)
        }
    }

    func errorCaught(context _: ChannelHandlerContext, error _: any Error) {
        fail(.unavailable)
    }

    func enqueue(_ operation: NIOAuthenticatedSMTPOperation) -> EventLoopFuture<Void> {
        let promise = context!.eventLoop.makePromise(of: Void.self)
        let future = promise.futureResult
        context!.eventLoop.execute {
            if self.completed {
                promise.fail(MailpitSMTPDeliveryError.unavailable)
                return
            }
            if self.pending == nil {
                self.pending = (operation, promise)
                self.beginPending()
            } else {
                self.pendingQueue.append((operation, promise))
            }
        }
        return future
    }

    private func beginPending() {
        guard let context, let pending else { return }
        switch pending.operation {
        case let .authenticate(username, password, mechanism):
            sendAuth(username: username, password: password, mechanism: mechanism, context: context)
        case let .send(to, subject, body):
            _ = (subject, body)
            phase = .mail
            send("MAIL FROM:<\(configuration.username ?? "")>\r\n", context: context)
            _ = to
        }
    }

    private func sendAuth(username: String, password: String, mechanism: SMTPAuthMechanism, context: ChannelHandlerContext) {
        switch mechanism {
        case .plain:
            let payload = "\0\(username)\0\(password)"
            let encoded = Data(payload.utf8).base64EncodedString()
            phase = .auth
            send("AUTH PLAIN \(encoded)\r\n", context: context)
        case .login:
            phase = .auth
            authStep = .loginUsername
            send("AUTH LOGIN\r\n", context: context)
        case .xoauth2:
            let payload = "user=\(username)\u{1}auth=Bearer \(password)\u{1}\u{1}"
            let encoded = Data(payload.utf8).base64EncodedString()
            phase = .auth
            send("AUTH XOAUTH2 \(encoded)\r\n", context: context)
        }
    }

    private func parseLines(_ context: ChannelHandlerContext) {
        while !completed,
              let lineFeed = inbound.readableBytesView.firstIndex(of: 0x0a) {
            let start = inbound.readerIndex
            guard lineFeed > start,
                  inbound.getInteger(at: lineFeed - 1, as: UInt8.self) == 0x0d else {
                fail(.protocolViolation)
                return
            }
            let lineLength = lineFeed - start - 1
            guard lineLength <= Self.maximumReplyLineBytes,
                  let line = inbound.readBytes(length: lineLength),
                  inbound.readInteger(as: UInt8.self) == 0x0d,
                  inbound.readInteger(as: UInt8.self) == 0x0a else {
                fail(.protocolViolation)
                return
            }
            processReplyLine(line, context: context)
        }
        guard completed || inbound.readableBytes <= Self.maximumReplyLineBytes + 2 else {
            fail(.protocolViolation)
            return
        }
        inbound.discardReadBytes()
    }

    private func processReplyLine(_ line: [UInt8], context: ChannelHandlerContext) {
        totalReplyLines += 1
        currentReplyLines += 1
        currentReplyBytes += line.count + 2
        guard totalReplyLines <= Self.maximumReplyLines,
              currentReplyLines <= Self.maximumLinesPerReply,
              currentReplyBytes <= Self.maximumBytesPerReply,
              line.count >= 4,
              line[0...2].allSatisfy({ (48 ... 57).contains($0) }),
              let code = Int(String(decoding: line[0...2], as: UTF8.self)),
              line[3] == 0x20 || line[3] == 0x2d else {
            fail(.protocolViolation)
            return
        }
        if let multilineCode {
            guard code == multilineCode else {
                fail(.protocolViolation)
                return
            }
            if line[3] == 0x20 {
                self.multilineCode = nil
                completeReply(code, context: context)
            }
        } else if line[3] == 0x2d {
            multilineCode = code
        } else {
            completeReply(code, context: context)
        }
    }

    private func completeReply(_ code: Int, context: ChannelHandlerContext) {
        currentReplyLines = 0
        currentReplyBytes = 0
        switch phase {
        case .greeting:
            guard code == 220 else {
                fail(.protocolViolation)
                return
            }
            phase = .ehlo
            send("EHLO swan\r\n", context: context)
        case .ehlo:
            guard code == 250 else {
                fail(.protocolViolation)
                return
            }
            if configuration.mode == .startTLS {
                phase = .startTLS
                send("STARTTLS\r\n", context: context)
            } else {
                phase = .finished
                readyPromise?.succeed(())
            }
        case .startTLS:
            guard code == 220 else {
                fail(.protocolViolation)
                return
            }
            phase = .tlsHandshake
            do {
                let handler = try NIOSSLClientHandler(
                    context: tlsContext,
                    serverHostname: configuration.expectedHostname ?? configuration.host
                )
                context.pipeline.addHandler(handler).whenComplete { [weak self] result in
                    guard let self else { return }
                    switch result {
                    case .success:
                        self.phase = .ehloAfterTLS
                        self.send("EHLO swan\r\n", context: context)
                    case .failure:
                        self.fail(.unavailable)
                    }
                }
            } catch {
                fail(.unavailable)
            }
        case .ehloAfterTLS:
            guard code == 250 else {
                fail(.protocolViolation)
                return
            }
            phase = .finished
            readyPromise?.succeed(())
        case .tlsHandshake:
            // During the TLS handshake the NIOSSL handler consumes the
            // channel bytes; an SMTP reply here is a protocol violation.
            fail(.protocolViolation)
        case .auth:
            switch authStep {
            case .loginUsername:
                guard code == 334 else {
                    fail(.protocolViolation)
                    return
                }
                if case let .authenticate(username, _, _) = pending?.operation {
                    authStep = .loginPassword
                    send("\(Data(username.utf8).base64EncodedString())\r\n", context: context)
                } else {
                    fail(.protocolViolation)
                }
            case .loginPassword:
                guard code == 334 else {
                    fail(.protocolViolation)
                    return
                }
                if case let .authenticate(_, password, _) = pending?.operation {
                    authStep = .none
                    send("\(Data(password.utf8).base64EncodedString())\r\n", context: context)
                } else {
                    fail(.protocolViolation)
                }
            case .none:
                guard code == 235 else {
                    fail(.protocolViolation)
                    return
                }
                finishPending()
            }
        case .mail:
            guard code == 250 else {
                fail(.protocolViolation)
                return
            }
            if case .send = pending?.operation {
                phase = .recipient
                if case let .send(to, _, _) = pending?.operation {
                    send("RCPT TO:<\(to)>\r\n", context: context)
                }
            } else {
                fail(.protocolViolation)
            }
        case .recipient:
            guard code == 250 || code == 251 else {
                fail(.protocolViolation)
                return
            }
            phase = .data
            send("DATA\r\n", context: context)
        case .data:
            guard code == 354 else {
                fail(.protocolViolation)
                return
            }
            phase = .acceptance
            if case let .send(to, subject, body) = pending?.operation {
                let terminatedBody = body.hasSuffix("\r\n") ? body : "\(body)\r\n"
                let dataCommand = "From: <\(configuration.username ?? "")>\r\n"
                    + "To: <\(to)>\r\n"
                    + "Subject: \(subject)\r\n"
                    + "MIME-Version: 1.0\r\n"
                    + "Content-Type: text/plain; charset=us-ascii\r\n"
                    + "Content-Transfer-Encoding: 7bit\r\n"
                    + "\r\n"
                    + terminatedBody
                    + ".\r\n"
                send(dataCommand, context: context)
            } else {
                fail(.protocolViolation)
            }
        case .acceptance:
            guard code == 250 else {
                fail(.protocolViolation)
                return
            }
            phase = .quit
            send("QUIT\r\n", context: context)
        case .quit:
            guard code == 221 else {
                fail(.protocolViolation)
                return
            }
            phase = .finished
            finishPending()
        case .finished:
            fail(.protocolViolation)
        }
    }

    private func finishPending() {
        if let pending {
            let promise = pending.promise
            self.pending = nil
            promise.succeed(())
        }
        if !pendingQueue.isEmpty {
            let next = pendingQueue.removeFirst()
            pending = next
            beginPending()
        }
    }

    private func send(_ string: String, context: ChannelHandlerContext) {
        var buffer = context.channel.allocator.buffer(capacity: string.utf8.count)
        buffer.writeString(string)
        context.writeAndFlush(wrapOutboundOut(buffer)).whenFailure { [weak self] _ in
            self?.fail(.unavailable)
        }
    }

    private func fail(_ error: MailpitSMTPDeliveryError) {
        guard !completed else { return }
        completed = true
        completeAll(error)
    }

    private func completeAll(_ error: MailpitSMTPDeliveryError) {
        if let pending {
            pending.promise.fail(error)
            self.pending = nil
        }
        for queued in pendingQueue {
            queued.promise.fail(error)
        }
        pendingQueue.removeAll()
        if let readyPromise, !readyPromise.futureResult.isFulfilled {
            readyPromise.fail(error)
        }
        context?.close(promise: nil)
    }
}

private extension EventLoopFuture {
    var isFulfilled: Bool {
        var fulfilled = false
        whenComplete { _ in fulfilled = true }
        return fulfilled
    }
}
