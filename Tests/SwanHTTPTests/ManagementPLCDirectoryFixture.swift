import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
@testable import SwanAccounts

final class ManagementPLCDirectoryFixture: @unchecked Sendable {
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private let state: ManagementPLCFixtureState

    var port: Int { channel.localAddress!.port! }
    var submitCount: Int { state.submitCount }

    func setWellKnownResponse(_ response: ManagementPLCWellKnownResponse) {
        state.setWellKnownResponse(response)
    }

    init(submitBody: Data = Data("OK".utf8)) throws {
        group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let sharedState = ManagementPLCFixtureState(submitBody: submitBody)
        state = sharedState
        channel = try ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 8)
            .childChannelInitializer { channel in
                channel.pipeline.configureHTTPServerPipeline().flatMap {
                    channel.pipeline.addHandler(ManagementPLCFixtureHandler(state: sharedState))
                }
            }
            .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .bind(host: "127.0.0.1", port: 0)
            .wait()
    }

    func shutdown() {
        try? channel.close().wait()
        try? group.syncShutdownGracefully()
    }
}

final class ManagementPLCFixtureState: @unchecked Sendable {
    static let responseBodySentinel = "2026-07-27T12:34:56.789Z"
    static let proofBodySentinel = "did=did:plc:zyxwvutsrqponmlkjihgfedc"

    private let lock = NSLock()
    private let submitBody: Data
    private var audit: Data?
    private var document: Data?
    private var submittedDID: String?
    private var wellKnownResponse = ManagementPLCWellKnownResponse.automatic
    private var count = 0

    init(submitBody: Data) {
        self.submitBody = submitBody
    }

    var submitCount: Int {
        locked { count }
    }

    func submit(did: String, operationData: Data) throws -> Data {
        let operation = try PLCOperationCodec.decodeSignedJSON(operationData)
        let rawOperation = try JSONSerialization.jsonObject(with: operationData)
        guard let operationObject = rawOperation as? [String: Any],
              let rotationKeys = operationObject["rotationKeys"],
              let verificationMethods = operationObject["verificationMethods"],
              let alsoKnownAs = operationObject["alsoKnownAs"],
              let services = operationObject["services"] else {
            throw ManagementPLCFixtureError.malformedOperation
        }
        let audit = try JSONSerialization.data(withJSONObject: [[
            "did": did,
            "operation": rawOperation,
            "cid": try operation.cid.string,
            "nullified": false,
            "createdAt": Self.responseBodySentinel,
        ]], options: [.sortedKeys])
        let document = try JSONSerialization.data(withJSONObject: [
            "did": did,
            "rotationKeys": rotationKeys,
            "verificationMethods": verificationMethods,
            "alsoKnownAs": alsoKnownAs,
            "services": services,
        ], options: [.sortedKeys])
        locked {
            count += 1
            self.audit = audit
            self.document = document
            submittedDID = did
        }
        return submitBody
    }

    func currentAudit() -> Data? {
        locked { audit }
    }

    func currentDocument() -> Data? {
        locked { document }
    }

    func setWellKnownResponse(_ response: ManagementPLCWellKnownResponse) {
        locked {
            wellKnownResponse = response
        }
    }

    func currentWellKnownResponse() -> ManagementPLCWellKnownResponse {
        locked {
            switch wellKnownResponse {
            case .automatic:
                guard let submittedDID else { return .missing }
                return .body(Data(submittedDID.utf8))
            case let .body(body):
                return .body(body)
            case .missing:
                return .missing
            }
        }
    }

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }
}

enum ManagementPLCWellKnownResponse {
    case automatic
    case body(Data)
    case missing
}

private enum ManagementPLCFixtureError: Error {
    case malformedOperation
}

private final class ManagementPLCFixtureHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let state: ManagementPLCFixtureState
    private var head: HTTPRequestHead?
    private var body = Data()

    init(state: ManagementPLCFixtureState) {
        self.state = state
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case let .head(head):
            self.head = head
            body.removeAll(keepingCapacity: true)
        case let .body(buffer):
            body.append(contentsOf: buffer.readableBytesView)
        case .end:
            respond(context: context)
        }
    }

    private func respond(context: ChannelHandlerContext) {
        guard let head else {
            write(status: .badRequest, body: Data(), contentType: nil, context: context)
            return
        }
        if head.method == .GET, head.uri == "/.well-known/atproto-did" {
            switch state.currentWellKnownResponse() {
            case .automatic:
                write(status: .notFound, body: Data(), contentType: nil, context: context)
            case let .body(body):
                write(
                    status: .ok,
                    body: body,
                    contentType: "text/plain; charset=utf-8",
                    context: context
                )
            case .missing:
                write(status: .notFound, body: Data(), contentType: nil, context: context)
            }
            return
        }
        let components = head.uri.split(separator: "/", omittingEmptySubsequences: true)
        guard let did = components.first.map(String.init), did.hasPrefix("did:plc:") else {
            write(status: .notFound, body: Data(), contentType: nil, context: context)
            return
        }
        if head.method == .POST, components.count == 1 {
            do {
                let response = try state.submit(did: did, operationData: body)
                write(
                    status: .ok,
                    body: response,
                    contentType: "text/plain; charset=utf-8",
                    context: context
                )
            } catch {
                write(status: .badRequest, body: Data(), contentType: nil, context: context)
            }
        } else if head.method == .GET,
                  components.count == 3,
                  components[1] == "log",
                  components[2] == "audit",
                  let audit = state.currentAudit() {
            write(
                status: .ok,
                body: audit,
                contentType: "application/json; charset=utf-8",
                context: context
            )
        } else if head.method == .GET,
                  components.count == 2,
                  components[1] == "data",
                  let document = state.currentDocument() {
            write(
                status: .ok,
                body: document,
                contentType: "application/json; charset=utf-8",
                context: context
            )
        } else {
            write(status: .notFound, body: Data(), contentType: nil, context: context)
        }
    }

    private func write(
        status: HTTPResponseStatus,
        body: Data,
        contentType: String?,
        context: ChannelHandlerContext
    ) {
        var headers = HTTPHeaders()
        headers.add(name: "content-length", value: String(body.count))
        if let contentType { headers.add(name: "content-type", value: contentType) }
        headers.add(name: "connection", value: "close")
        context.write(
            wrapOutboundOut(.head(.init(version: .http1_1, status: status, headers: headers))),
            promise: nil
        )
        if !body.isEmpty {
            var buffer = context.channel.allocator.buffer(capacity: body.count)
            buffer.writeBytes(body)
            context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        }
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
    }
}
