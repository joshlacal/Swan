import NIOCore
import NIOHTTPTypes

/// Marks the current HTTP/1 request body as no longer visible to the
/// application while leaving the socket readable. The decoder can therefore
/// consume and discard bytes that arrive after an admitted-body deadline
/// instead of leaving unread bytes to turn the response close into a TCP RST.
final class SwanJSONWriteBodyDrainHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = HTTPRequestPart
    typealias InboundOut = HTTPRequestPart

    private var isDiscarding = false
    private let requestTimeout: TimeAmount
    private var requestDeadline: Scheduled<Void>?
    private var forcedClose: Scheduled<Void>?
    private var handlerContext: ChannelHandlerContext?
    init(timeout: Duration) {
        let components = timeout.components
        let seconds = components.seconds.multipliedReportingOverflow(by: 1_000_000_000)
        let fraction = components.attoseconds / 1_000_000_000
        let combined = seconds.partialValue.addingReportingOverflow(fraction)
        requestTimeout = .nanoseconds(
            seconds.overflow || combined.overflow ? Int64.max : max(1, combined.partialValue)
        )
    }

    func handlerAdded(context: ChannelHandlerContext) {
        handlerContext = context
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head:
            isDiscarding = false
            requestDeadline?.cancel()
            requestDeadline = context.eventLoop.scheduleTask(in: requestTimeout) {
                self.expireRequest()
            }
        case .end:
            requestDeadline?.cancel()
            requestDeadline = nil
        case .body:
            break
        }
        guard isDiscarding else {
            context.fireChannelRead(data)
            return
        }

    }

    func channelReadComplete(context: ChannelHandlerContext) {
        if isDiscarding {
            // Bypass the downstream NIOAsyncChannel handler, whose source was
            // intentionally finished and therefore no longer requests reads.
            context.read()
        }
        context.fireChannelReadComplete()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        guard event is SwanJSONWriteBodyDrainEvent else {
            context.fireUserInboundEventTriggered(event)
            return
        }
        guard !isDiscarding else { return }
        beginDiscarding(context: context)
    }

    func channelInactive(context: ChannelHandlerContext) {
        requestDeadline?.cancel()
        forcedClose?.cancel()
        requestDeadline = nil
        forcedClose = nil
        handlerContext = nil
        context.fireChannelInactive()
    }

    private func expireRequest() {
        guard let context = handlerContext else { return }
        beginDiscarding(context: context)
        forcedClose = context.eventLoop.scheduleTask(in: .milliseconds(50)) {
            self.handlerContext?.close(mode: .all, promise: nil)
        }
    }

    private func beginDiscarding(context: ChannelHandlerContext) {
        guard !isDiscarding else { return }
        isDiscarding = true
        // The application collector is released so it can construct the
        // sanitized failure response. Streaming commits independently require
        // exact Content-Length accounting, so this signal cannot authorize a
        // truncated upload.
        context.fireUserInboundEventTriggered(ChannelEvent.inputClosed)
        context.read()
    }

}

struct SwanJSONWriteBodyDrainEvent: Sendable {}
