import Crypto
import Dispatch
import Foundation
import NIOCore
import NIOPosix
import SwanStorage

public enum AccountEmailDeliveryCancellationContract: Sendable, Equatable {
    /// The implementation has a bounded cancellation path. Once the caller
    /// cancels `deliver`, it must stop before the durable outbox fence can be
    /// reclaimed. This is an explicit capability rather than an assumption
    /// made from the protocol's `async` shape.
    case bounded

    /// The implementation cannot prove that cancellation stops network work.
    /// Swan refuses to attach such a delivery to the durable recovery worker:
    /// a late SMTP completion could otherwise race lease reclamation or
    /// permanent account deletion.
    case unverified
}

public protocol AccountEmailDelivery: Sendable {
    /// Implementations must explicitly declare their cancellation contract.
    /// The value is nonisolated so the recovery service can reject an
    /// unverified implementation before it claims any durable delivery.
    nonisolated var cancellationContract:
        AccountEmailDeliveryCancellationContract { get }

    func deliver(to: AccountEmailAddress, subject: String, body: String) async throws
}

public enum MailpitSMTPDeliveryError: Error, Sendable, Equatable {
    case invalidConfiguration
    case invalidMessage
    case admissionFull
    case shutDown
    case timedOut
    case protocolViolation
    case unavailable
}

/// A bounded, reply-driven SMTP client for the isolated Mailpit laboratory.
///
/// One instance owns and reuses its event-loop group. Its lifecycle owner must
/// call `shutdown()` during service teardown; shutdown rejects queued/new work,
/// closes every active SMTP channel, drains admitted deliveries, and then
/// closes the shared group.
public actor MailpitSMTPDelivery: AccountEmailDelivery {
    public nonisolated var cancellationContract:
        AccountEmailDeliveryCancellationContract { .bounded }

    private let host: String
    private let port: Int
    private let sender: AccountEmailAddress
    private let connectTimeout: TimeInterval
    private let commandTimeout: TimeInterval
    private let maximumConcurrentDeliveries: Int
    private let maximumPendingDeliveries: Int
    private let group: MultiThreadedEventLoopGroup

    private struct AdmissionWaiter {
        let id: UUID
        let continuation: CheckedContinuation<Void, Error>
    }

    private var activeDeliveries = 0
    private var admissionWaiters: [AdmissionWaiter] = []
    private var drainWaiters: [CheckedContinuation<Void, Never>] = []
    private var shutdownWaiters: [CheckedContinuation<Void, Error>] = []
    private var activeChannels: [ObjectIdentifier: Channel] = [:]
    private var shutdownStarted = false
    private var shutdownResult: Result<Void, MailpitSMTPDeliveryError>?

    public init(
        host: String = "mailpit",
        port: Int = 1025,
        sender: AccountEmailAddress,
        connectTimeout: TimeInterval = 5,
        commandTimeout: TimeInterval = 5,
        maximumConcurrentDeliveries: Int = 4,
        maximumPendingDeliveries: Int = 32
    ) throws {
        let canonicalHost = host.lowercased()
        guard (1 ... 65_535).contains(port),
              ["mailpit", "127.0.0.1", "localhost", "::1"].contains(canonicalHost),
              connectTimeout.isFinite, (0.01 ... 30).contains(connectTimeout),
              commandTimeout.isFinite, (0.01 ... 30).contains(commandTimeout),
              (1 ... 32).contains(maximumConcurrentDeliveries),
              (0 ... 1_024).contains(maximumPendingDeliveries),
              Self.safeMailbox(sender.value) else {
            throw MailpitSMTPDeliveryError.invalidConfiguration
        }
        self.host = canonicalHost
        self.port = port
        self.sender = sender
        self.connectTimeout = connectTimeout
        self.commandTimeout = commandTimeout
        self.maximumConcurrentDeliveries = maximumConcurrentDeliveries
        self.maximumPendingDeliveries = maximumPendingDeliveries
        self.group = MultiThreadedEventLoopGroup(
            numberOfThreads: min(maximumConcurrentDeliveries, 2)
        )
    }

    public func deliver(to: AccountEmailAddress, subject: String, body: String) async throws {
        guard Self.safeMailbox(to.value),
              Self.safeHeader(subject),
              Self.safeBody(body) else {
            throw MailpitSMTPDeliveryError.invalidMessage
        }
        let message = SMTPMessage(
            sender: sender.value,
            recipient: to.value,
            subject: subject,
            dotStuffedBody: Self.dotStuff(body)
        )
        try await acquireAdmission()
        defer { releaseAdmission() }
        try Task.checkCancellation()
        try await send(message)
    }

    /// Idempotently drains admitted work and releases the shared NIO resource.
    public func shutdown() async throws {
        if let shutdownResult {
            return try shutdownResult.get()
        }
        if shutdownStarted {
            return try await withCheckedThrowingContinuation {
                shutdownWaiters.append($0)
            }
        }
        shutdownStarted = true
        let queued = admissionWaiters
        admissionWaiters.removeAll(keepingCapacity: false)
        queued.forEach {
            $0.continuation.resume(
                throwing: MailpitSMTPDeliveryError.shutDown
            )
        }
        let channels = Array(activeChannels.values)
        for channel in channels {
            channel.close(promise: nil)
        }
        if activeDeliveries > 0 {
            await withCheckedContinuation { drainWaiters.append($0) }
        }

        let result: Result<Void, MailpitSMTPDeliveryError>
        do {
            try await group.shutdownGracefully()
            result = .success(())
        } catch {
            result = .failure(.unavailable)
        }
        shutdownResult = result
        let waiters = shutdownWaiters
        shutdownWaiters.removeAll(keepingCapacity: false)
        for waiter in waiters {
            switch result {
            case .success:
                waiter.resume()
            case let .failure(error):
                waiter.resume(throwing: error)
            }
        }
        return try result.get()
    }

    private func acquireAdmission() async throws {
        guard !shutdownStarted else {
            throw MailpitSMTPDeliveryError.shutDown
        }
        if activeDeliveries < maximumConcurrentDeliveries {
            activeDeliveries += 1
            return
        }
        guard admissionWaiters.count < maximumPendingDeliveries else {
            throw MailpitSMTPDeliveryError.admissionFull
        }

        let id = UUID()
        try await withTaskCancellationHandler(
            operation: { [self] () async throws -> Void in
                try await suspendForAdmission(id: id)
            },
            onCancel: {
                Task { await self.cancelAdmission(id: id) }
            }
        )
    }

    private func suspendForAdmission(id: UUID) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            guard !Task.isCancelled else {
                continuation.resume(throwing: CancellationError())
                return
            }
            admissionWaiters.append(.init(
                id: id,
                continuation: continuation
            ))
        }
    }

    private func cancelAdmission(id: UUID) {
        guard let index = admissionWaiters.firstIndex(where: { $0.id == id })
        else { return }
        let waiter = admissionWaiters.remove(at: index)
        waiter.continuation.resume(throwing: CancellationError())
    }

    private func releaseAdmission() {
        precondition(activeDeliveries > 0)
        if !shutdownStarted, !admissionWaiters.isEmpty {
            let waiter = admissionWaiters.removeFirst()
            waiter.continuation.resume()
            return
        }
        activeDeliveries -= 1
        if shutdownStarted, activeDeliveries == 0 {
            let waiters = drainWaiters
            drainWaiters.removeAll(keepingCapacity: false)
            waiters.forEach { $0.resume() }
        }
    }

    private func send(_ message: SMTPMessage) async throws {
        let completion = group.next().makePromise(of: Void.self)
        let timeout = commandTimeout
        let bootstrap = ClientBootstrap(group: group)
            .connectTimeout(.milliseconds(Int64(connectTimeout * 1_000)))
            .channelOption(
                ChannelOptions.socket(
                    SocketOptionLevel(IPPROTO_TCP),
                    TCP_NODELAY
                ),
                value: 1
            )
            .channelInitializer { channel in
                channel.pipeline.addHandler(SMTPClientHandler(
                    message: message,
                    timeout: timeout,
                    completion: completion
                ))
            }

        let channel: Channel
        do {
            channel = try await bootstrap.connect(host: host, port: port).get()
        } catch ChannelError.connectTimeout(_) {
            throw MailpitSMTPDeliveryError.timedOut
        } catch {
            throw MailpitSMTPDeliveryError.unavailable
        }
        guard !shutdownStarted else {
            try? await channel.close().get()
            throw MailpitSMTPDeliveryError.shutDown
        }
        let channelID = ObjectIdentifier(channel)
        activeChannels[channelID] = channel
        defer { activeChannels.removeValue(forKey: channelID) }
        do {
            try await withTaskCancellationHandler {
                try await completion.futureResult.get()
            } onCancel: {
                channel.close(promise: nil)
            }
            try? await channel.close().get()
        } catch let error as MailpitSMTPDeliveryError {
            try? await channel.close().get()
            throw error
        } catch is CancellationError {
            try? await channel.close().get()
            throw CancellationError()
        } catch {
            try? await channel.close().get()
            throw MailpitSMTPDeliveryError.unavailable
        }
    }

    private static func safeMailbox(_ value: String) -> Bool {
        AccountEmailAddress.isCanonicalMailbox(value)
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
        return value.split(
            separator: "\n",
            omittingEmptySubsequences: false
        ).allSatisfy { line in
            line.utf8.count <= (line.first == "." ? 997 : 998)
        }
    }

    private static func dotStuff(_ value: String) -> String {
        value.split(
            separator: "\n",
            omittingEmptySubsequences: false
        ).map { line in
            line.first == "." ? ".\(line)" : String(line)
        }.joined(separator: "\r\n")
    }
}

private struct SMTPMessage: Sendable {
    let sender: String
    let recipient: String
    let subject: String
    let dotStuffedBody: String

    var dataCommand: String {
        let terminatedBody = dotStuffedBody.hasSuffix("\r\n")
            ? dotStuffedBody
            : "\(dotStuffedBody)\r\n"
        return "From: <\(sender)>\r\n"
            + "To: <\(recipient)>\r\n"
            + "Subject: \(subject)\r\n"
            + "MIME-Version: 1.0\r\n"
            + "Content-Type: text/plain; charset=us-ascii\r\n"
            + "Content-Transfer-Encoding: 7bit\r\n"
            + "\r\n"
            + terminatedBody
            + ".\r\n"
    }
}

/// NIO invokes this handler exclusively on one channel event loop. Mutable
/// parser/protocol state never escapes that loop; only the completion promise
/// crosses back to Swift concurrency. TODO(SWAN-SMTP-001): remove the
/// unchecked conformance when NIO exposes a checked event-loop-confined
/// handler annotation.
private final class SMTPClientHandler:
    ChannelInboundHandler,
    @unchecked Sendable
{
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private enum Phase {
        case greeting
        case ehlo
        case mail
        case recipient
        case data
        case acceptance
        case quit
        case finished
    }

    private static let maximumReplyLineBytes = 1_000
    private static let maximumReplyLines = 64
    private static let maximumReplyBytes = 32 * 1_024
    private static let maximumLinesPerReply = 32
    private static let maximumBytesPerReply = 8 * 1_024

    private let message: SMTPMessage
    private let timeout: TimeInterval
    private let completion: EventLoopPromise<Void>
    private var phase = Phase.greeting
    private var inbound = ByteBuffer()
    private var totalReplyLines = 0
    private var totalReplyBytes = 0
    private var currentReplyLines = 0
    private var currentReplyBytes = 0
    private var multilineCode: Int?
    private var timeoutTask: Scheduled<Void>?
    private var completed = false
    private weak var handlerContext: ChannelHandlerContext?

    init(
        message: SMTPMessage,
        timeout: TimeInterval,
        completion: EventLoopPromise<Void>
    ) {
        self.message = message
        self.timeout = timeout
        self.completion = completion
    }

    func handlerAdded(context: ChannelHandlerContext) {
        handlerContext = context
    }

    func channelActive(context: ChannelHandlerContext) {
        armTimeout(context)
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var bytes = unwrapInboundIn(data)
        totalReplyBytes += bytes.readableBytes
        guard totalReplyBytes <= Self.maximumReplyBytes else {
            fail(context, .protocolViolation)
            return
        }
        inbound.writeBuffer(&bytes)
        parseLines(context)
    }

    func channelInactive(context: ChannelHandlerContext) {
        if !completed { fail(context, .unavailable) }
    }

    func errorCaught(
        context: ChannelHandlerContext,
        error _: any Error
    ) {
        fail(context, .unavailable)
    }

    func handlerRemoved(context _: ChannelHandlerContext) {
        timeoutTask?.cancel()
        handlerContext = nil
    }

    private func parseLines(_ context: ChannelHandlerContext) {
        while !completed,
              let lineFeed = inbound.readableBytesView.firstIndex(of: 0x0a) {
            let start = inbound.readerIndex
            guard lineFeed > start,
                  inbound.getInteger(
                      at: lineFeed - 1,
                      as: UInt8.self
                  ) == 0x0d else {
                fail(context, .protocolViolation)
                return
            }
            let lineLength = lineFeed - start - 1
            guard lineLength <= Self.maximumReplyLineBytes,
                  let line = inbound.readBytes(length: lineLength),
                  inbound.readInteger(as: UInt8.self) == 0x0d,
                  inbound.readInteger(as: UInt8.self) == 0x0a else {
                fail(context, .protocolViolation)
                return
            }
            processReplyLine(line, context: context)
        }
        guard completed
                || inbound.readableBytes <= Self.maximumReplyLineBytes + 2
        else {
            fail(context, .protocolViolation)
            return
        }
        inbound.discardReadBytes()
    }

    private func processReplyLine(
        _ line: [UInt8],
        context: ChannelHandlerContext
    ) {
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
            fail(context, .protocolViolation)
            return
        }

        if let multilineCode {
            guard code == multilineCode else {
                fail(context, .protocolViolation)
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

    private func completeReply(
        _ code: Int,
        context: ChannelHandlerContext
    ) {
        currentReplyLines = 0
        currentReplyBytes = 0
        switch phase {
        case .greeting:
            guard code == 220 else {
                fail(context, .protocolViolation)
                return
            }
            phase = .ehlo
            send("EHLO swan-lab\r\n", context: context)
        case .ehlo:
            guard code == 250 else {
                fail(context, .protocolViolation)
                return
            }
            phase = .mail
            send("MAIL FROM:<\(message.sender)>\r\n", context: context)
        case .mail:
            guard code == 250 else {
                fail(context, .protocolViolation)
                return
            }
            phase = .recipient
            send("RCPT TO:<\(message.recipient)>\r\n", context: context)
        case .recipient:
            guard code == 250 || code == 251 else {
                fail(context, .protocolViolation)
                return
            }
            phase = .data
            send("DATA\r\n", context: context)
        case .data:
            guard code == 354 else {
                fail(context, .protocolViolation)
                return
            }
            phase = .acceptance
            send(message.dataCommand, context: context)
        case .acceptance:
            guard code == 250 else {
                fail(context, .protocolViolation)
                return
            }
            phase = .quit
            send("QUIT\r\n", context: context)
        case .quit:
            guard code == 221 else {
                fail(context, .protocolViolation)
                return
            }
            phase = .finished
            finish(context)
        case .finished:
            fail(context, .protocolViolation)
        }
    }

    private func send(
        _ string: String,
        context: ChannelHandlerContext
    ) {
        armTimeout(context)
        var buffer = context.channel.allocator.buffer(
            capacity: string.utf8.count
        )
        buffer.writeString(string)
        context.writeAndFlush(wrapOutboundOut(buffer)).whenFailure {
            [weak self] _ in
            self?.failFromCallback(.unavailable)
        }
    }

    private func armTimeout(_ context: ChannelHandlerContext) {
        timeoutTask?.cancel()
        timeoutTask = context.eventLoop.scheduleTask(
            in: .milliseconds(Int64(timeout * 1_000))
        ) { [weak self] in
            self?.failFromCallback(.timedOut)
        }
    }

    private func failFromCallback(_ error: MailpitSMTPDeliveryError) {
        guard let handlerContext else { return }
        fail(handlerContext, error)
    }

    private func finish(_ context: ChannelHandlerContext) {
        guard !completed else { return }
        completed = true
        timeoutTask?.cancel()
        completion.succeed(())
        context.close(promise: nil)
    }

    private func fail(
        _ context: ChannelHandlerContext,
        _ error: MailpitSMTPDeliveryError
    ) {
        guard !completed else { return }
        completed = true
        timeoutTask?.cancel()
        completion.fail(error)
        context.close(promise: nil)
    }
}

public enum AccountEmailRecoveryError: Error, Sendable, Equatable {
    case invalidProofKey
    case invalidProof
    case accountNotFound
    case invalidEmail
    case capacityExhausted
    case deliveryUnavailable
}

/// Required process secret for proof and rate-limit HMAC derivation. The
/// value belongs in an environment variable or mounted secret and is never
/// represented by a storage-layer type.
public struct AccountEmailProofKey: Sendable {
    fileprivate let bytes: Data

    public init(_ bytes: Data) throws {
        guard bytes.count == 32 else {
            throw AccountEmailRecoveryError.invalidProofKey
        }
        self.bytes = bytes
    }
}

/// Domain-separated HMAC codec. A random delivery ID is durable; its bearer
/// proof and the digest stored beside account state are independently derived.
public struct AccountEmailProofCodec: Sendable {
    private static let proofDomain =
        Data("swan.account-email.proof.v1\u{0}".utf8)
    private static let digestDomain =
        Data("swan.account-email.proof-digest.v1\u{0}".utf8)
    private static let lookupDomain =
        Data("swan.account-email.lookup.v1\u{0}".utf8)
    private static let envelopeDomain =
        Data("swan.account-email.recovery-envelope.v1\u{0}".utf8)
    private static let rateDomain =
        Data("swan.account-email.rate-limit.v1\u{0}".utf8)

    private let key: AccountEmailProofKey

    public init(key: AccountEmailProofKey) {
        self.key = key
    }

    public func proof(for deliveryID: AccountEmailDeliveryID) -> String {
        Self.base64URL(
            authenticate(
                Self.proofDomain + Data(deliveryID.rawValue.utf8)
            )
        )
    }

    public func digest(proof: String) throws -> Data {
        guard Self.isBase64URL256(proof) else {
            throw AccountEmailRecoveryError.invalidProof
        }
        return authenticate(Self.digestDomain + Data(proof.utf8))
    }

    /// Returns a keyed marker for a canonical address. The marker is used to
    /// perform blind password-recovery work for unknown addresses without
    /// storing or exposing their plaintext mailbox value.
    public func lookupDigest(email: AccountEmailAddress) -> Data {
        authenticate(Self.lookupDomain + Data(email.value.utf8))
    }

    /// Seals the canonical mailbox for the asynchronous recovery queue. The
    /// queue stores this envelope even for unknown addresses, so the HTTP
    /// request performs the same bounded write regardless of account existence.
    /// The lookup digest is authenticated as associated data and is checked
    /// again when the worker opens the envelope.
    public func recoveryEmailEnvelope(
        for email: AccountEmailAddress
    ) throws -> Data {
        let lookup = lookupDigest(email: email)
        let authenticatedData = Self.envelopeDomain + lookup
        let sealed = try AES.GCM.seal(
            Data(email.value.utf8),
            using: SymmetricKey(data: key.bytes),
            authenticating: authenticatedData
        )
        guard let combined = sealed.combined,
              (28 ... 4_096).contains(combined.count) else {
            throw AccountEmailRecoveryError.invalidProof
        }
        return combined
    }

    /// Opens and validates a recovery queue envelope. A tampered envelope or
    /// a digest/address mismatch is intentionally mapped to the same opaque
    /// invalid-proof error used for malformed bearer proofs.
    public func email(
        fromRecoveryEnvelope envelope: Data,
        expectedLookupDigest: Data
    ) throws -> AccountEmailAddress {
        guard expectedLookupDigest.count == 32,
              (28 ... 4_096).contains(envelope.count) else {
            throw AccountEmailRecoveryError.invalidProof
        }
        let sealed: AES.GCM.SealedBox
        do {
            sealed = try AES.GCM.SealedBox(combined: envelope)
        } catch {
            throw AccountEmailRecoveryError.invalidProof
        }
        let opened: Data
        do {
            opened = try AES.GCM.open(
                sealed,
                using: SymmetricKey(data: key.bytes),
                authenticating: Self.envelopeDomain + expectedLookupDigest
            )
        } catch {
            throw AccountEmailRecoveryError.invalidProof
        }
        let address: AccountEmailAddress
        do {
            address = try AccountEmailAddress(
                String(decoding: opened, as: UTF8.self)
            )
        } catch {
            throw AccountEmailRecoveryError.invalidProof
        }
        guard lookupDigest(email: address) == expectedLookupDigest else {
            throw AccountEmailRecoveryError.invalidProof
        }
        return address
    }

    public func rateLimitKey(
        scope: AccountEmailRateLimitScope,
        value: String
    ) throws -> AccountEmailRateLimitKey {
        let bytes = Array(value.utf8)
        guard (1 ... 1_024).contains(bytes.count),
              bytes.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e }) else {
            throw AccountEmailRecoveryError.invalidProof
        }
        let input = Self.rateDomain
            + Data(scope.rawValue.utf8)
            + Data([0])
            + Data(bytes)
        return try AccountEmailRateLimitKey(
            scope: scope,
            digest: authenticate(input)
        )
    }

    public func newDeliveryID() throws -> AccountEmailDeliveryID {
        var generator = SystemRandomNumberGenerator()
        let bytes = Data(
            (0 ..< 32).map {
                _ in UInt8.random(in: 0 ... 255, using: &generator)
            }
        )
        return try AccountEmailDeliveryID(rawValue: Self.base64URL(bytes))
    }

    private func authenticate(_ input: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(
            for: input,
            using: SymmetricKey(data: key.bytes)
        ))
    }

    private static func isBase64URL256(_ value: String) -> Bool {
        value.utf8.count == 43 && value.utf8.allSatisfy {
            (48 ... 57).contains($0)
                || (65 ... 90).contains($0)
                || (97 ... 122).contains($0)
                || $0 == 45 || $0 == 95
        }
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

public struct Argon2idHashMetrics: Sendable, Equatable {
    public let active: Int
    public let queued: Int
    public let peakActive: Int
    public let totalAdmitted: Int
    public let totalRejected: Int
}

/// Bounds password-reset hashing on an actor and moves libsodium's blocking
/// Argon2id work to a dedicated Dispatch queue.
public actor Argon2idHashExecutor {
    private typealias HashOperation = @Sendable (String) throws -> String

    private struct PendingHash {
        let id: UUID
        let password: String
        let continuation: CheckedContinuation<String, any Error>
    }

    public let maximumConcurrentHashes: Int
    public let maximumQueuedHashes: Int
    private let blockingQueue: DispatchQueue
    private let operation: HashOperation
    private var pending: [PendingHash] = []
    private var active = 0
    private var peakActive = 0
    private var totalAdmitted = 0
    private var totalRejected = 0

    public init(
        hasher: LibsodiumArgon2idHasher,
        maximumConcurrentHashes: Int = 2,
        maximumQueuedHashes: Int = 32
    ) throws {
        try Self.validateBounds(
            maximumConcurrentHashes,
            maximumQueuedHashes
        )
        self.maximumConcurrentHashes = maximumConcurrentHashes
        self.maximumQueuedHashes = maximumQueuedHashes
        blockingQueue = DispatchQueue(
            label: "org.swan.accounts.argon2id.hash",
            qos: .userInitiated,
            attributes: .concurrent
        )
        operation = { try hasher.hash($0) }
    }

    init(
        maximumConcurrentHashes: Int,
        maximumQueuedHashes: Int = 32,
        operation: @escaping @Sendable (String) throws -> String
    ) throws {
        try Self.validateBounds(
            maximumConcurrentHashes,
            maximumQueuedHashes
        )
        self.maximumConcurrentHashes = maximumConcurrentHashes
        self.maximumQueuedHashes = maximumQueuedHashes
        blockingQueue = DispatchQueue(
            label: "org.swan.accounts.argon2id.hash.test",
            attributes: .concurrent
        )
        self.operation = operation
    }

    public func hash(_ password: String) async throws -> String {
        try Task.checkCancellation()
        let requestID = UUID()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<String, any Error>) in
                if Task.isCancelled {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                if active >= maximumConcurrentHashes,
                   pending.count >= maximumQueuedHashes {
                    totalRejected += 1
                    continuation.resume(
                        throwing: AccountEmailRecoveryError.capacityExhausted
                    )
                    return
                }
                pending.append(PendingHash(
                    id: requestID,
                    password: password,
                    continuation: continuation
                ))
                scheduleAdmittedWork()
            }
        } onCancel: {
            Task { await self.cancelQueued(requestID) }
        }
    }

    public func metrics() -> Argon2idHashMetrics {
        Argon2idHashMetrics(
            active: active,
            queued: pending.count,
            peakActive: peakActive,
            totalAdmitted: totalAdmitted,
            totalRejected: totalRejected
        )
    }

    private func scheduleAdmittedWork() {
        while active < maximumConcurrentHashes, !pending.isEmpty {
            let request = pending.removeFirst()
            active += 1
            peakActive = max(peakActive, active)
            totalAdmitted += 1
            let operation = self.operation
            blockingQueue.async {
                let result = Result {
                    try operation(request.password)
                }
                Task { await self.complete(request, result: result) }
            }
        }
    }

    private func complete(
        _ request: PendingHash,
        result: Result<String, any Error>
    ) {
        active -= 1
        request.continuation.resume(with: result)
        scheduleAdmittedWork()
    }

    private func cancelQueued(_ requestID: UUID) {
        guard let index = pending.firstIndex(where: { $0.id == requestID })
        else { return }
        let request = pending.remove(at: index)
        request.continuation.resume(throwing: CancellationError())
        scheduleAdmittedWork()
    }

    private static func validateBounds(
        _ maximumConcurrentHashes: Int,
        _ maximumQueuedHashes: Int
    ) throws {
        guard (1 ... 4).contains(maximumConcurrentHashes),
              (0 ... 1_024).contains(maximumQueuedHashes) else {
            throw AccountControlStoreError.invalidInput
        }
    }
}

public enum AccountEmailDeliveryRunResult: Sendable, Equatable {
    case idle
    case delivered(AccountEmailDeliveryID)
    case retryScheduled(AccountEmailDeliveryID, nextAttemptAt: Date)
    case expired(AccountEmailDeliveryID)
}

/// Durable account recovery coordinator. Raw bearer proofs exist only while a
/// delivery body or exact confirmation/reset request is being processed.
public actor AccountEmailRecoveryService {
    /// Keep a margin below the SQLite pre-network fence. Mailpit's maximum
    /// configured SMTP exchange (connect plus bounded command deadlines) is
    /// below this value, while a stalled/cancelled delivery cannot remain in
    /// flight until the durable lease is reclaimable.
    public static let maximumDeliveryAttemptTimeout: TimeInterval = 240

    private let store: any AccountControlStore
    private let delivery: any AccountEmailDelivery
    private let proofCodec: AccountEmailProofCodec
    private let hashExecutor: Argon2idHashExecutor
    private let tokenLifetime: TimeInterval
    private let retryPolicy: AccountEmailRetryPolicy
    private let deliveryLeaseDuration: TimeInterval
    private let deliveryAttemptTimeout: TimeInterval

    public init(
        store: any AccountControlStore,
        delivery: any AccountEmailDelivery,
        proofCodec: AccountEmailProofCodec,
        hashExecutor: Argon2idHashExecutor,
        tokenLifetime: TimeInterval = 900,
        retryPolicy: AccountEmailRetryPolicy = .standard,
        deliveryLeaseDuration: TimeInterval = 30,
        deliveryAttemptTimeout: TimeInterval = 240
    ) throws {
        guard tokenLifetime.isFinite,
              (60 ... 86_400).contains(tokenLifetime),
              deliveryLeaseDuration.isFinite,
              (1 ... 300).contains(deliveryLeaseDuration),
              deliveryAttemptTimeout.isFinite,
              (0.01 ... Self.maximumDeliveryAttemptTimeout)
                .contains(deliveryAttemptTimeout),
              delivery.cancellationContract == .bounded else {
            throw AccountControlStoreError.invalidInput
        }
        self.store = store
        self.delivery = delivery
        self.proofCodec = proofCodec
        self.hashExecutor = hashExecutor
        self.tokenLifetime = tokenLifetime
        self.retryPolicy = retryPolicy
        self.deliveryLeaseDuration = deliveryLeaseDuration
        self.deliveryAttemptTimeout = deliveryAttemptTimeout
    }

    public func requestEmailConfirmation(
        did: String,
        email: AccountEmailAddress,
        now: Date = Date()
    ) async throws {
        let deliveryID = try proofCodec.newDeliveryID()
        let proof = proofCodec.proof(for: deliveryID)
        let request = try AccountEmailProofDeliveryRequest(
            deliveryID: deliveryID,
            did: did,
            email: email,
            purpose: .verifyEmail,
            proofDigest: proofCodec.digest(proof: proof),
            expiresAt: now.addingTimeInterval(tokenLifetime),
            now: now
        )
        switch try await store.enqueueEmailProofDelivery(request) {
        case .enqueued:
            return
        case .accountNotFound:
            throw AccountEmailRecoveryError.accountNotFound
        case .invalidEmail:
            throw AccountEmailRecoveryError.invalidEmail
        }
    }

    /// Always returns successfully for a canonical request regardless of
    /// whether it matched a verified active account.
    public func requestPasswordRecovery(
        email: AccountEmailAddress,
        now: Date = Date()
    ) async throws {
        let deliveryID = try proofCodec.newDeliveryID()
        let proof = proofCodec.proof(for: deliveryID)
        let emailEnvelope = try proofCodec.recoveryEmailEnvelope(for: email)
        try await store.enqueuePasswordRecoveryDelivery(
            AccountPasswordRecoveryDeliveryRequest(
                deliveryID: deliveryID,
                proofDigest: proofCodec.digest(proof: proof),
                email: email,
                lookupDigest: proofCodec.lookupDigest(email: email),
                emailEnvelope: emailEnvelope,
                expiresAt: now.addingTimeInterval(tokenLifetime),
                now: now
            )
        )
    }

    public func deliverNext(
        workerID: String,
        now: Date = Date()
    ) async throws -> AccountEmailDeliveryRunResult {
        // Resolve at most one account-free request before claiming SMTP work.
        // This keeps account lookup, token replacement, and outbox insertion
        // outside the user-visible password-reset transaction while retaining
        // durable restart/retry behavior.
        try await materializeNextPasswordRecovery(
            workerID: workerID,
            now: now
        )
        guard let lease = try await store.claimNextEmailDelivery(
            workerID: workerID,
            now: now,
            leaseDuration: deliveryLeaseDuration
        ) else {
            return .idle
        }
        let proof = proofCodec.proof(for: lease.deliveryID)
        let subject = lease.purpose == .verifyEmail
            ? "Verify your Swan email"
            : "Reset your Swan password"
        do {
            // Claiming a row is not enough to authorize SMTP: permanent
            // deletion can win the next SQLite transaction and scrub the
            // outbox before a worker reaches this point. The storage fence
            // is the linearization point immediately before network I/O.
            guard try await store.beginEmailDeliveryAttempt(
                deliveryID: lease.deliveryID,
                workerID: workerID,
                now: now
            ) else {
                throw AccountEmailRecoveryError.deliveryUnavailable
            }
            try await deliverWithDeadline(
                to: lease.email,
                subject: subject,
                body: "Swan proof token: \(proof)"
            )
            let acknowledged = try await store.acknowledgeEmailDelivery(
                deliveryID: lease.deliveryID,
                workerID: workerID,
                now: now
            )
            guard acknowledged else {
                throw AccountEmailRecoveryError.deliveryUnavailable
            }
            return .delivered(lease.deliveryID)
        } catch {
            switch try await store.retryEmailDelivery(
                deliveryID: lease.deliveryID,
                workerID: workerID,
                now: now,
                policy: retryPolicy
            ) {
            case let .scheduled(nextAttemptAt):
                return .retryScheduled(
                    lease.deliveryID,
                    nextAttemptAt: nextAttemptAt
                )
            case .expired:
                return .expired(lease.deliveryID)
            }
        }
    }

    private func materializeNextPasswordRecovery(
        workerID: String,
        now: Date
    ) async throws {
        guard let work = try await store.claimNextPasswordRecoveryWork(
            workerID: workerID,
            now: now,
            leaseDuration: deliveryLeaseDuration
        ) else {
            return
        }

        let email: AccountEmailAddress
        do {
            email = try proofCodec.email(
                fromRecoveryEnvelope: work.emailEnvelope,
                expectedLookupDigest: work.lookupDigest
            )
        } catch {
            // Authenticated-invalid work cannot become a bearer token. Drop
            // only this leased row; never log or reflect its contents.
            try? await store.discardPasswordRecoveryWork(
                work,
                workerID: workerID,
                now: now
            )
            return
        }

        // Storage failures are deliberately not treated as bad envelopes.
        // Let the durable lease expire and requeue the work rather than
        // discarding a valid reset request during a transient SQLite error.
        _ = try await store.materializePasswordRecoveryWork(
            work,
            email: email,
            workerID: workerID,
            now: now
        )
    }

    private func deliverWithDeadline(
        to email: AccountEmailAddress,
        subject: String,
        body: String
    ) async throws {
        let delivery = self.delivery
        let timeoutMilliseconds = Int64(
            (deliveryAttemptTimeout * 1_000).rounded(.up)
        )
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await delivery.deliver(
                    to: email,
                    subject: subject,
                    body: body
                )
            }
            group.addTask {
                try await Task.sleep(
                    for: .milliseconds(timeoutMilliseconds)
                )
                throw AccountEmailRecoveryError.deliveryUnavailable
            }
            defer { group.cancelAll() }
            try await group.next()
        }
    }

    public func confirmEmail(
        did: String,
        email: AccountEmailAddress,
        proof: String,
        now: Date = Date()
    ) async throws -> AccountEmailConfirmationOutcome {
        let digest: Data
        do {
            digest = try proofCodec.digest(proof: proof)
        } catch {
            return .invalidToken
        }
        return try await store.confirmEmailProof(
            AccountEmailConfirmationRequest(
                did: did,
                email: email,
                proofDigest: digest
            ),
            now: now
        )
    }

    public func resetPassword(
        proof: String,
        password: String,
        now: Date = Date()
    ) async throws -> AccountPasswordResetOutcome {
        // The pinned TypeScript handler rejects passwords longer than 256
        // characters. Swan applies the stricter UTF-8 byte interpretation so
        // hashing admission is bounded before any Unicode expansion work and
        // never accepts a password the reference host would reject.
        guard (8 ... 256).contains(password.utf8.count) else {
            return .invalidToken
        }
        let digest: Data
        do {
            digest = try proofCodec.digest(proof: proof)
        } catch {
            return .invalidToken
        }
        let lookup = try await store.passwordRecoveryLookup(
            proofDigest: digest,
            now: now
        )
        let confirmation: AccountPasswordRecoveryConfirmation
        switch lookup {
        case let .ready(value):
            confirmation = value
        case .expiredToken:
            return .expiredToken
        case .invalidToken:
            return .invalidToken
        }
        let replacement = try await hashExecutor.hash(password)
        guard let credential = try await store.credential(
            did: confirmation.did
        ) else {
            // Perform the bounded Argon2 work before the account lookup so a
            // valid proof for a deleted/tombstoned account does not take the
            // cheap path while a live account takes the expensive path.
            return .invalidToken
        }
        let request = try AccountPasswordRecoveryRequest(
            confirmation: confirmation,
            expectedVerifier: credential.verifier,
            replacementVerifier: replacement
        )
        switch try await store.completePasswordRecovery(request, now: now) {
        case .completed:
            return .completed
        case .unchanged:
            let current = try await store.passwordRecoveryLookup(
                proofDigest: digest,
                now: now
            )
            return current == .expiredToken ? .expiredToken : .invalidToken
        }
    }
}
