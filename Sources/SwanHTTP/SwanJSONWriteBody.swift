import Foundation
import Hummingbird
import NIOConcurrencyHelpers
import NIOCore
import SwanStorage

/// One total elapsed-time policy for every admitted, allocation-heavy JSON
/// command body. The deadline is independent of the listener's idle timeout:
/// receiving another chunk does not reset it.
public final class SwanJSONWriteBodyPolicy: Sendable {
    /// Long enough for a legitimate 1 MiB command on a slow connection while
    /// still placing a finite bound on anonymous admission ownership.
    public static let productionDefault = try! SwanJSONWriteBodyPolicy(
        totalBodyTimeout: .seconds(30)
    )

    public let totalBodyTimeout: Duration

    public init(totalBodyTimeout: Duration) throws {
        guard totalBodyTimeout > .zero else {
            throw SwanJSONWriteBodyPolicyError.invalidTotalBodyTimeout
        }
        self.totalBodyTimeout = totalBodyTimeout
    }
}

public enum SwanJSONWriteBodyPolicyError: Error, Sendable, Equatable {
    case invalidTotalBodyTimeout
}

enum SwanJSONWriteBodyCollectionFailure: Error {
    case invalidRequest
    case unavailable
}

enum SwanRequestBodyCollectionFailure: Error, Equatable {
    case invalidRequest
    case payloadTooLarge
    case unavailable
}

enum SwanRequestBodyMediaType: Sendable {
    case json
    case formURLEncoded
    case unspecified

    fileprivate func accepts(_ values: [String]) -> Bool {
        if case .unspecified = self {
            return values.count <= 1
        }
        guard values.count == 1 else { return false }
        let pieces = values[0]
            .split(separator: ";", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        switch self {
        case .json:
            return pieces.first?.lowercased() == "application/json"
        case .formURLEncoded:
            return pieces.first?.lowercased() == "application/x-www-form-urlencoded"
                && (pieces.count == 1
                    || pieces.count == 2 && pieces[1].lowercased() == "charset=utf-8")
        case .unspecified:
            return true
        }
    }
}

struct SwanRequestBodyAdmissionConfiguration: Sendable {
    let admission: PublicRepositoryJSONWriteAdmission
    let policy: SwanJSONWriteBodyPolicy
}

final class SwanAdmittedRequestBody: @unchecked Sendable {
    let buffer: ByteBuffer
    private let lease: PublicRepositoryJSONWriteLease

    init(buffer: ByteBuffer, lease: PublicRepositoryJSONWriteLease) {
        self.buffer = buffer
        self.lease = lease
    }

    var readableBytes: Int { buffer.readableBytes }
    var readerIndex: Int { buffer.readerIndex }
    var readableBytesView: ByteBufferView { buffer.readableBytesView }
    func getBytes(at index: Int, length: Int) -> [UInt8]? {
        buffer.getBytes(at: index, length: length)
    }

    func release() { lease.release() }
    deinit { lease.release() }
}

/// Required termination capability paired with one concrete inbound body.
/// Production routes can obtain it only from their request context; tests use
/// the internal initializer to model an independently terminable body source.
struct SwanJSONWriteBodyTerminationHandle: Sendable {
    private let action: @Sendable () -> Void
    private let state: @Sendable () async -> Bool

    init(
        _ action: @escaping @Sendable () -> Void,
        state: @escaping @Sendable () async -> Bool = { false }
    ) {
        self.action = action
        self.state = state
    }

    func terminate() {
        action()
    }

    func wasTerminated() async -> Bool { await state() }
}

/// Request-scoped termination state shared by every handle derived from one
/// Hummingbird request context. Keeping this value outside the channel handler
/// avoids moving `ChannelHandlerContext` across Swift concurrency boundaries;
/// the actual pipeline mutation remains scheduled by NIO on its event loop.
final class SwanJSONWriteBodyTerminationState: Sendable {
    private let terminated = NIOLockedValueBox(false)

    var value: Bool { terminated.withLockedValue { $0 } }

    func markTerminated() {
        terminated.withLockedValue { $0 = true }
    }
}

/// Collects one buffered public-listener body under process-wide admission
/// and a finite absolute elapsed-time bound. Header rejection happens before
/// memory is reserved and always terminates the unread request stream.
func collectAdmittedRequestBody(
    _ request: Request,
    mediaType: SwanRequestBodyMediaType,
    admission: PublicRepositoryJSONWriteAdmission,
    policy: SwanJSONWriteBodyPolicy,
    maximumBytes: Int,
    termination: SwanJSONWriteBodyTerminationHandle
) async throws -> SwanAdmittedRequestBody {
    if let failure = requestBodyHeaderFailure(
        request, mediaType: mediaType, maximumBytes: maximumBytes
    ) {
        do {
            try await drainRejectedRequestBody(
                request,
                admission: admission,
                policy: policy,
                termination: termination
            )
        } catch {
            throw SwanRequestBodyCollectionFailure.unavailable
        }
        throw failure
    }
    guard let lease = admission.reserve(maximumRequestBytes: maximumBytes) else {
        termination.terminate()
        throw SwanRequestBodyCollectionFailure.unavailable
    }
    do {
        let buffer = try await collectRequestBody(
            request.body,
            maximumBytes: maximumBytes,
            timeout: policy.totalBodyTimeout,
            termination: termination
        )
        return SwanAdmittedRequestBody(buffer: buffer, lease: lease)
    } catch is NIOTooManyBytesError {
        lease.release()
        termination.terminate()
        throw SwanRequestBodyCollectionFailure.payloadTooLarge
    } catch is CancellationError {
        lease.release()
        throw SwanRequestBodyCollectionFailure.unavailable
    } catch is SwanRequestBodyDeadlineExceeded {
        lease.release()
        throw SwanRequestBodyCollectionFailure.unavailable
    } catch {
        lease.release()
        throw SwanRequestBodyCollectionFailure.invalidRequest
    }
}

func validateRequestBodyHeaders(
    _ request: Request,
    mediaType: SwanRequestBodyMediaType,
    maximumBytes: Int,
    termination: SwanJSONWriteBodyTerminationHandle
) throws {
    if let failure = requestBodyHeaderFailure(
        request, mediaType: mediaType, maximumBytes: maximumBytes
    ) {
        termination.terminate()
        throw failure
    }
}

private func requestBodyHeaderFailure(
    _ request: Request,
    mediaType: SwanRequestBodyMediaType,
    maximumBytes: Int
) -> SwanRequestBodyCollectionFailure? {
    guard mediaType.accepts(request.headers[values: .contentType]) else {
        return .invalidRequest
    }
    switch boundedContentLength(
        request.headers[values: .contentLength],
        maximumBytes: maximumBytes
    ) {
    case .valid:
        return nil
    case .invalid:
        return .invalidRequest
    case .tooLarge:
        return .payloadTooLarge
    }
}

func drainRejectedRequestBody(
    _ request: Request,
    admission: PublicRepositoryJSONWriteAdmission,
    policy: SwanJSONWriteBodyPolicy,
    termination: SwanJSONWriteBodyTerminationHandle
) async throws {
    // Rejected bodies are discarded chunk-by-chunk and do not reserve their
    // declared payload size, but each incomplete drain still owns a listener
    // slot. A one-byte lease therefore enforces the shared concurrency bound
    // without charging the JSON memory budget for bytes we never retain.
    guard let lease = admission.reserve(maximumRequestBytes: 1) else {
        termination.terminate()
        throw SwanRequestBodyCollectionFailure.unavailable
    }
    defer { lease.release() }
    let body = request.body
    try await withAbsoluteRequestBodyDeadline(
        policy: policy,
        termination: termination
    ) {
        var iterator = body.makeAsyncIterator()
        while try await iterator.next() != nil {
            try Task.checkCancellation()
        }
    }
}

private enum SwanBoundedContentLength {
    case valid
    case invalid
    case tooLarge
}

private func boundedContentLength(
    _ values: [String],
    maximumBytes: Int
) -> SwanBoundedContentLength {
    guard values.count <= 1 else { return .invalid }
    guard let value = values.first else { return .valid }
    guard !value.isEmpty,
          value.utf8.allSatisfy({ (48 ... 57).contains($0) }),
          let length = Int(value) else {
        return .invalid
    }
    return length <= maximumBytes ? .valid : .tooLarge
}

/// Keeps the admission lease in this stack frame across collection, strict
/// decoding, authorization, persistence, and both success and failure
/// response construction. Returning only `Response` prevents a production
/// caller from selecting the decoded input as the helper's result and letting
/// it escape after the lease is released.
func withAdmittedJSONWriteResponse<Value>(
    _ body: RequestBody,
    admission: PublicRepositoryJSONWriteAdmission,
    policy: SwanJSONWriteBodyPolicy,
    maximumBytes: Int,
    expectedBytes: Int? = nil,
    termination: SwanJSONWriteBodyTerminationHandle,
    decode: (Data) throws -> Value,
    operation: (Value) async throws -> Response,
    errorResponse: (any Error) -> Response
) async -> Response {
    guard let lease = admission.reserve(maximumRequestBytes: maximumBytes) else {
        termination.terminate()
        return errorResponse(SwanJSONWriteBodyCollectionFailure.unavailable)
    }
    defer { lease.release() }

    do {
        let buffer = try await collectRequestBody(
            body,
            maximumBytes: maximumBytes,
            timeout: policy.totalBodyTimeout,
            termination: termination
        )
        if let expectedBytes, buffer.readableBytes != expectedBytes {
            throw SwanJSONWriteBodyCollectionFailure.unavailable
        }
        guard buffer.readableBytes > 0,
              let bytes = buffer.getBytes(
                  at: buffer.readerIndex,
                  length: buffer.readableBytes
              ) else {
            throw SwanJSONWriteBodyCollectionFailure.invalidRequest
        }
        return try await operation(try decode(Data(bytes)))
    } catch is NIOTooManyBytesError {
        termination.terminate()
        return errorResponse(SwanJSONWriteBodyCollectionFailure.invalidRequest)
    } catch is CancellationError {
        return errorResponse(SwanJSONWriteBodyCollectionFailure.unavailable)
    } catch is SwanRequestBodyDeadlineExceeded {
        return errorResponse(SwanJSONWriteBodyCollectionFailure.unavailable)
    } catch {
        return errorResponse(error)
    }
}

private struct SwanRequestBodyDeadlineExceeded: Error {}

private enum SwanJSONWriteBodyTermination {
    case none
    case deadline
    case cancellation
}

func withAbsoluteRequestBodyDeadline<Value: Sendable>(
    policy: SwanJSONWriteBodyPolicy,
    termination bodyTermination: SwanJSONWriteBodyTerminationHandle,
    operation: @escaping @Sendable () async throws -> Value
) async throws -> Value {
    let termination = NIOLockedValueBox(SwanJSONWriteBodyTermination.none)
    do {
        return try await withTaskCancellationHandler {
            try await withThrowingTaskGroup(of: Value.self) { group in
                group.addTask(operation: operation)
                group.addTask {
                    try await Task.sleep(for: routeBodyTimeout(policy.totalBodyTimeout))
                    try Task.checkCancellation()
                    let ownsTermination = termination.withLockedValue { state in
                        guard case .none = state else { return false }
                        state = .deadline
                        return true
                    }
                    if ownsTermination { bodyTermination.terminate() }
                    throw SwanRequestBodyDeadlineExceeded()
                }
                defer { group.cancelAll() }
                guard let first = try await group.next() else {
                    throw SwanRequestBodyDeadlineExceeded()
                }
                switch termination.withLockedValue({ $0 }) {
                case .none:
                    return first
                case .deadline:
                    throw SwanRequestBodyDeadlineExceeded()
                case .cancellation:
                    throw CancellationError()
                }
            }
        } onCancel: {
            let ownsTermination = termination.withLockedValue { state in
                guard case .none = state else { return false }
                state = .cancellation
                return true
            }
            if ownsTermination { bodyTermination.terminate() }
        }
    } catch is SwanRequestBodyDeadlineExceeded {
        throw SwanRequestBodyCollectionFailure.unavailable
    } catch is CancellationError {
        throw SwanRequestBodyCollectionFailure.unavailable
    }
}

private func collectRequestBody(
    _ body: RequestBody,
    maximumBytes: Int,
    timeout: Duration,
    termination bodyTermination: SwanJSONWriteBodyTerminationHandle
) async throws -> ByteBuffer {
    let termination = NIOLockedValueBox(SwanJSONWriteBodyTermination.none)
    return try await withTaskCancellationHandler {
        try await withThrowingTaskGroup(of: ByteBuffer.self) { group in
            group.addTask {
                try await body.collect(upTo: maximumBytes)
            }
            group.addTask {
                try await Task.sleep(for: routeBodyTimeout(timeout))
                try Task.checkCancellation()
                let ownsTermination = termination.withLockedValue { state in
                    guard case .none = state else { return false }
                    state = .deadline
                    return true
                }
                if ownsTermination {
                    bodyTermination.terminate()
                }
                throw SwanRequestBodyDeadlineExceeded()
            }
            defer { group.cancelAll() }
            guard let first = try await group.next() else {
                throw SwanRequestBodyDeadlineExceeded()
            }
            switch termination.withLockedValue({ $0 }) {
            case .none:
                return first
            case .deadline:
                throw SwanRequestBodyDeadlineExceeded()
            case .cancellation:
                throw CancellationError()
            }
        }
    } onCancel: {
        let ownsTermination = termination.withLockedValue { state in
            guard case .none = state else { return false }
            state = .cancellation
            return true
        }
        if ownsTermination {
            bodyTermination.terminate()
        }
    }
}

private func routeBodyTimeout(_ listenerTimeout: Duration) -> Duration {
    let lead = Duration.milliseconds(5)
    return listenerTimeout > lead ? listenerTimeout - lead : listenerTimeout
}
