import Hummingbird
import HTTPTypes
import Logging
import NIOConcurrencyHelpers
import NIOCore
import NIOEmbedded
import SwanStorage
import XCTest
@testable import SwanHTTP

final class JSONWriteBodyAdmissionHTTPTests: XCTestCase, @unchecked Sendable {
    func testAggregateAdmissionRemainsHeldAfterCollectionForStrictParsing() async throws {
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: 1_024
        )
        let request = Request(
            head: HTTPRequest(
                method: .post, scheme: "https", authority: "swan.example", path: "/parse",
                headerFields: [.contentType: "application/json", .contentLength: "2"]
            ),
            body: .init(buffer: ByteBuffer(string: "{}"))
        )

        let body = try await collectAdmittedRequestBody(
            request,
            mediaType: .json,
            admission: admission,
            policy: try SwanJSONWriteBodyPolicy(totalBodyTimeout: .seconds(1)),
            maximumBytes: 1_024,
            termination: .init({})
        )

        XCTAssertNil(
            admission.reserve(maximumRequestBytes: 1_024),
            "strict parsing must still own the sole aggregate reservation"
        )
        body.release()
    }

    func testDeadlineCannotTurnTruncatedStreamingBodyIntoSuccessfulCommit() async throws {
        let policy = try SwanJSONWriteBodyPolicy(totalBodyTimeout: .milliseconds(40))
        let committed = NIOLockedValueBox(false)

        do {
            _ = try await withAbsoluteRequestBodyDeadline(
                policy: policy,
                termination: .init({})
            ) {
                try await Task.sleep(for: .seconds(5))
                try Task.checkCancellation()
                committed.withLockedValue { $0 = true }
                return ()
            }
            XCTFail("a truncated body must fail")
        } catch {
            // Expected deadline failure.
        }

        XCTAssertFalse(
            committed.withLockedValue { $0 },
            "deadline termination must not synthesize a successful EOF"
        )
    }

    func testSharedFormCollectorPreservesCompleteBody() async throws {
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: 1_024
        )
        let text = "client_id=https%3A%2F%2Fclient.example&state=complete"
        let request = Request(
            head: HTTPRequest(
                method: .post,
                scheme: "https",
                authority: "swan.example",
                path: "/oauth/par",
                headerFields: [
                    .contentType: "application/x-www-form-urlencoded",
                    .contentLength: String(text.utf8.count),
                ]
            ),
            body: .init(buffer: ByteBuffer(string: text))
        )

        let body = try await collectAdmittedRequestBody(
            request,
            mediaType: .formURLEncoded,
            admission: admission,
            policy: try SwanJSONWriteBodyPolicy(totalBodyTimeout: .seconds(1)),
            maximumBytes: 1_024,
            termination: .init({})
        )

        XCTAssertEqual(String(decoding: body.readableBytesView, as: UTF8.self), text)
        body.release()
        XCTAssertEqual(admission.snapshot, .init(activeLeases: 0, reservedRequestBytes: 0))
    }

    func testSharedCollectorTerminatesMalformedContentLengthBeforeAdmission() async throws {
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: 1_024
        )
        let terminations = NIOLockedValueBox(0)
        let request = Request(
            head: HTTPRequest(
                method: .post,
                scheme: "https",
                authority: "swan.example",
                path: "/oauth/par",
                headerFields: [
                    .contentType: "application/x-www-form-urlencoded",
                    .contentLength: "+12",
                ]
            ),
            body: .init(asyncSequence: AsyncStream<ByteBuffer> { _ in })
        )

        do {
            _ = try await collectAdmittedRequestBody(
                request,
                mediaType: .formURLEncoded,
                admission: admission,
                policy: try SwanJSONWriteBodyPolicy(totalBodyTimeout: .milliseconds(40)),
                maximumBytes: 1_024,
                termination: .init {
                    terminations.withLockedValue { $0 += 1 }
                }
            )
            XCTFail("malformed Content-Length must reject")
        } catch let failure as SwanRequestBodyCollectionFailure {
            XCTAssertEqual(failure, .unavailable)
        }
        XCTAssertEqual(terminations.withLockedValue { $0 }, 1)
        XCTAssertEqual(admission.snapshot, .init(activeLeases: 0, reservedRequestBytes: 0))
    }

    func testAdmissionRefusalTerminatesUnreadBody() async throws {
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: 1_024
        )
        let held = try XCTUnwrap(
            admission.reserve(maximumRequestBytes: 1_024)
        )
        defer { held.release() }
        let terminations = NIOLockedValueBox(0)

        let response = await withAdmittedJSONWriteResponse(
            RequestBody(asyncSequence: AsyncStream<ByteBuffer> { _ in }),
            admission: admission,
            policy: try SwanJSONWriteBodyPolicy(totalBodyTimeout: .seconds(1)),
            maximumBytes: 1_024,
            termination: .init {
                terminations.withLockedValue { $0 += 1 }
            },
            decode: { _ in () },
            operation: { _ in
                XCTFail("admission refusal must precede collection")
                return Response(status: .ok)
            },
            errorResponse: { _ in Response(status: .serviceUnavailable) }
        )

        XCTAssertEqual(response.status, .serviceUnavailable)
        XCTAssertEqual(terminations.withLockedValue { $0 }, 1)
        XCTAssertEqual(
            admission.snapshot,
            .init(activeLeases: 1, reservedRequestBytes: 1_024)
        )
    }

    func testRejectedBodyDrainsAreConcurrencyAdmittedBeforeWaitingForEOF() async throws {
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: 1_024
        )
        let policy = try SwanJSONWriteBodyPolicy(totalBodyTimeout: .seconds(1))
        let firstSource = NonCooperativeBodySource()
        let firstRequest = Request(
            head: HTTPRequest(
                method: .post, scheme: nil, authority: nil, path: "/rejected/first"
            ),
            body: .init(asyncSequence: NonCooperativeBodySequence(source: firstSource))
        )
        let firstDrain = Task {
            try await drainRejectedRequestBody(
                firstRequest,
                admission: admission,
                policy: policy,
                termination: .init(firstSource.terminate)
            )
        }
        defer {
            firstSource.terminate()
            firstDrain.cancel()
        }

        for _ in 0 ..< 100 where admission.snapshot.activeLeases == 0 {
            await Task.yield()
        }
        XCTAssertEqual(admission.snapshot.activeLeases, 1)

        let secondSource = NonCooperativeBodySource()
        let secondRequest = Request(
            head: HTTPRequest(
                method: .post, scheme: nil, authority: nil, path: "/rejected/second"
            ),
            body: .init(asyncSequence: NonCooperativeBodySequence(source: secondSource))
        )
        do {
            try await drainRejectedRequestBody(
                secondRequest,
                admission: admission,
                policy: policy,
                termination: .init(secondSource.terminate)
            )
            XCTFail("a second rejected body must not wait without admission")
        } catch let failure as SwanRequestBodyCollectionFailure {
            XCTAssertEqual(failure, .unavailable)
        }
        XCTAssertEqual(secondSource.terminationCount, 1)
        XCTAssertEqual(admission.snapshot.activeLeases, 1)

        firstSource.terminate()
        _ = try await firstDrain.value
        XCTAssertEqual(
            admission.snapshot,
            .init(activeLeases: 0, reservedRequestBytes: 0)
        )
    }

    func testOversizedBodyTerminatesUnreadRemainderAndReleasesAdmission() async throws {
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: 4
        )
        let terminations = NIOLockedValueBox(0)

        let response = await withAdmittedJSONWriteResponse(
            RequestBody(buffer: ByteBuffer(string: "12345")),
            admission: admission,
            policy: try SwanJSONWriteBodyPolicy(totalBodyTimeout: .seconds(1)),
            maximumBytes: 4,
            termination: .init {
                terminations.withLockedValue { $0 += 1 }
            },
            decode: { _ in () },
            operation: { _ in
                XCTFail("oversized body must not decode")
                return Response(status: .ok)
            },
            errorResponse: { _ in Response(status: .badRequest) }
        )

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(terminations.withLockedValue { $0 }, 1)
        XCTAssertEqual(
            admission.snapshot,
            .init(activeLeases: 0, reservedRequestBytes: 0)
        )
    }

    func testTotalDeadlineStopsPeriodicDripAndReleasesAdmission() async throws {
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: 1_024
        )
        let policy = try SwanJSONWriteBodyPolicy(
            totalBodyTimeout: .milliseconds(60)
        )
        let (stream, continuation) = AsyncStream.makeStream(of: ByteBuffer.self)
        let emissions = DripEmissionCounter()
        let producer = Task {
            while !Task.isCancelled {
                continuation.yield(ByteBuffer(string: " "))
                await emissions.increment()
                try await Task.sleep(for: .milliseconds(10))
            }
        }
        defer {
            producer.cancel()
            continuation.finish()
        }

        let started = ContinuousClock().now
        let response = await withAdmittedJSONWriteResponse(
            RequestBody(asyncSequence: stream),
            admission: admission,
            policy: policy,
            maximumBytes: 1_024,
            termination: .init(continuation.finish),
            decode: { _ in () },
            operation: { _ in
                XCTFail("deadline must precede end-of-body")
                return Response(status: .ok)
            },
            errorResponse: { error in
                guard case .unavailable = error as? SwanJSONWriteBodyCollectionFailure else {
                    XCTFail("deadline mapped to \(error)")
                    return Response(status: .badRequest)
                }
                XCTAssertEqual(admission.snapshot.activeLeases, 1)
                return Response(status: .serviceUnavailable)
            }
        )
        let elapsed = started.duration(to: ContinuousClock().now)
        let emissionCount = await emissions.value
        XCTAssertEqual(response.status, .serviceUnavailable)
        XCTAssertGreaterThanOrEqual(elapsed, .milliseconds(50))
        XCTAssertLessThan(elapsed, .seconds(1))
        XCTAssertGreaterThanOrEqual(emissionCount, 3)
        XCTAssertEqual(
            admission.snapshot,
            .init(activeLeases: 0, reservedRequestBytes: 0)
        )
    }

    func testDeadlineTerminatesCancellationResistantIteratorWithoutOrphaningCollector() async throws {
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: 1_024
        )
        let policy = try SwanJSONWriteBodyPolicy(totalBodyTimeout: .milliseconds(40))
        let source = NonCooperativeBodySource()
        let body = RequestBody(asyncSequence: NonCooperativeBodySequence(source: source))

        let started = ContinuousClock().now
        let response = await withAdmittedJSONWriteResponse(
            body,
            admission: admission,
            policy: policy,
            maximumBytes: 1_024,
            termination: .init(source.terminate),
            decode: { _ in () },
            operation: { _ in
                XCTFail("terminated iterator must not decode")
                return Response(status: .ok)
            },
            errorResponse: { error in
                guard case .unavailable = error as? SwanJSONWriteBodyCollectionFailure else {
                    XCTFail("deadline mapped to \(error)")
                    return Response(status: .badRequest)
                }
                XCTAssertEqual(admission.snapshot.activeLeases, 1)
                return Response(status: .serviceUnavailable)
            }
        )

        XCTAssertEqual(response.status, .serviceUnavailable)
        XCTAssertLessThan(started.duration(to: ContinuousClock().now), .seconds(1))
        XCTAssertEqual(source.terminationCount, 1)
        XCTAssertEqual(
            admission.snapshot,
            .init(activeLeases: 0, reservedRequestBytes: 0)
        )
    }

    func testFailureResponseIsConstructedBeforeLeaseRelease() async throws {
        struct HandlerFailure: Error {}

        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: 1_024
        )
        let policy = try SwanJSONWriteBodyPolicy(totalBodyTimeout: .seconds(1))
        let response = await withAdmittedJSONWriteResponse(
            RequestBody(buffer: ByteBuffer(string: "{}")),
            admission: admission,
            policy: policy,
            maximumBytes: 1_024,
            termination: .init({}),
            decode: { _ in () },
            operation: { _ in throw HandlerFailure() },
            errorResponse: { error in
                XCTAssertTrue(error is HandlerFailure)
                XCTAssertEqual(admission.snapshot.activeLeases, 1)
                return Response(status: .serviceUnavailable)
            }
        )

        XCTAssertEqual(response.status, .serviceUnavailable)
        XCTAssertEqual(
            admission.snapshot,
            .init(activeLeases: 0, reservedRequestBytes: 0)
        )
    }

    /// `NIOAsyncTestingChannel` uses `EmbeddedChannelCore`, which treats every
    /// close mode as an all-close. This test proves only that the context
    /// terminator wakes an NIO async iterator. The real SocketChannel
    /// input-half-close and response-delivery proof lives in
    /// `PublicRepositoryMutationHTTPTests`.
    func testEmbeddedChannelContextTerminationWakesNIOBackedBodyCollection() async throws {
        let channel = NIOAsyncTestingChannel()
        let asyncChannel = try await channel.testingEventLoop.executeInContext {
            try NIOAsyncChannel<ByteBuffer, Never>(
                wrappingChannelSynchronously: channel
            )
        }
        let context = SwanHTTPRequestContext(
            source: .init(
                channel: channel,
                logger: Logger(label: "JSONWriteBodyAdmissionHTTPTests.nio-half-close")
            )
        )
        let admission = try PublicRepositoryJSONWriteAdmission(
            maximumConcurrentWrites: 1,
            maximumReservedRequestBytes: 1_024
        )
        let policy = try SwanJSONWriteBodyPolicy(totalBodyTimeout: .milliseconds(40))
        let started = ContinuousClock().now

        let response = try await asyncChannel.executeThenClose { inbound, _ in
            let eventLoopPump = Task {
                while !Task.isCancelled {
                    await channel.testingEventLoop.run()
                    await Task.yield()
                }
            }
            let boundedAllClose = Task {
                try await Task.sleep(for: .seconds(1))
                channel.close(mode: .all, promise: nil)
            }
            defer {
                eventLoopPump.cancel()
                boundedAllClose.cancel()
            }

            let response = await withAdmittedJSONWriteResponse(
                RequestBody(asyncSequence: inbound),
                admission: admission,
                policy: policy,
                maximumBytes: 1_024,
                termination: context.jsonWriteBodyTermination,
                decode: { _ in () },
                operation: { _ in
                    XCTFail("half-closed body must not decode")
                    return Response(status: .ok)
                },
                errorResponse: { _ in
                    XCTAssertEqual(admission.snapshot.activeLeases, 1)
                    return Response(status: .serviceUnavailable)
                }
            )
            eventLoopPump.cancel()
            boundedAllClose.cancel()
            _ = await eventLoopPump.result
            _ = await boundedAllClose.result
            return response
        }

        XCTAssertEqual(response.status, .serviceUnavailable)
        XCTAssertLessThan(started.duration(to: ContinuousClock().now), .milliseconds(500))
        XCTAssertEqual(
            admission.snapshot,
            .init(activeLeases: 0, reservedRequestBytes: 0)
        )
    }

    func testInvalidTotalDeadlineConfigurationFailsClosed() throws {
        XCTAssertThrowsError(
            try SwanJSONWriteBodyPolicy(totalBodyTimeout: .zero)
        ) { error in
            XCTAssertEqual(
                error as? SwanJSONWriteBodyPolicyError,
                .invalidTotalBodyTimeout
            )
        }
        XCTAssertThrowsError(
            try SwanJSONWriteBodyPolicy(totalBodyTimeout: .seconds(-1))
        )
    }
}

private struct NonCooperativeBodySequence: AsyncSequence, Sendable {
    typealias Element = ByteBuffer

    let source: NonCooperativeBodySource

    func makeAsyncIterator() -> Iterator {
        Iterator(source: source)
    }

    struct Iterator: AsyncIteratorProtocol, Sendable {
        let source: NonCooperativeBodySource

        mutating func next() async throws -> ByteBuffer? {
            await source.next()
        }
    }
}

private final class NonCooperativeBodySource: @unchecked Sendable {
    private enum State {
        case idle
        case waiting(CheckedContinuation<ByteBuffer?, Never>)
        case terminated
    }

    private let state = NIOLockedValueBox(State.idle)
    private let terminations = NIOLockedValueBox(0)

    var terminationCount: Int { terminations.withLockedValue { $0 } }

    func next() async -> ByteBuffer? {
        await withCheckedContinuation { continuation in
            state.withLockedValue { state in
                switch state {
                case .idle:
                    state = .waiting(continuation)
                case .waiting:
                    preconditionFailure("request-body sequence is unicast")
                case .terminated:
                    continuation.resume(returning: nil)
                }
            }
        }
    }

    func terminate() {
        terminations.withLockedValue { $0 += 1 }
        let continuation = state.withLockedValue { state -> CheckedContinuation<ByteBuffer?, Never>? in
            switch state {
            case .idle:
                state = .terminated
                return nil
            case .waiting(let continuation):
                state = .terminated
                return continuation
            case .terminated:
                return nil
            }
        }
        continuation?.resume(returning: nil)
    }
}

private actor DripEmissionCounter {
    private(set) var value = 0

    func increment() {
        value += 1
    }
}
