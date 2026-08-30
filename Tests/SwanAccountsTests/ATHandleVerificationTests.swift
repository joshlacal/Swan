import CATHandleDNS
import Foundation
import PetrelPLC
@testable import SwanAccounts
import XCTest

final class ATHandleVerificationTests: XCTestCase {
    private let did = "did:plc:abcdefghijklmnopqrstuvwx"
    private let publicPeer = ATHandleIPAddress(literal: "8.8.8.8")!

    func testDNSCanonicalSuccessIsPreferredAndDoesNotFetchHTTP() async throws {
        let dns = FakeHandleDNS(
            txt: [.success([
                try txt("noise"),
                try ATHandleTXTRecord(bytes: Data([0xff, 0xfe])),
                try txt("did=\(did)"),
            ])],
            addresses: []
        )
        let http = FakeHandleHTTP([])
        let verifier = ATProtocolHandleVerifier(
            policy: try .production(),
            dns: dns,
            http: http
        )
        let verified = try await verifier.verify(
            plcState: state(handle: "alice.example.org"),
            expectedDID: did,
            handle: "Alice.Example.ORG",
            pdsOrigin: "https://pds.example.org"
        )
        XCTAssertEqual(verified.canonicalHandle, "alice.example.org")
        let txtNames = await dns.txtNames()
        let requests = await http.requests()
        XCTAssertEqual(txtNames, ["_atproto.alice.example.org"])
        XCTAssertEqual(requests, [])
    }

    func testReservedProductionTLDsFailBeforeNetwork() async throws {
        for tld in [
            "alt", "arpa", "example", "internal", "invalid", "local",
            "localhost", "onion", "test",
        ] {
            let dns = FakeHandleDNS(txt: [], addresses: [])
            let http = FakeHandleHTTP([])
            let handle = "alice.\(tld)"
            await assertVerificationFailure(
                try await ATProtocolHandleVerifier(
                    policy: try .production(),
                    dns: dns,
                    http: http
                ).verify(
                    plcState: state(handle: handle),
                    expectedDID: did,
                    handle: handle,
                    pdsOrigin: "https://pds.example.org"
                )
            )
            let txtNames = await dns.txtNames()
            let requests = await http.requests()
            XCTAssertEqual(txtNames, [])
            XCTAssertEqual(requests, [])
        }
    }

    func testNumericLeadingTLDIsRejectedBeforeNetwork() async throws {
        let dns = FakeHandleDNS(txt: [], addresses: [])
        let http = FakeHandleHTTP([])
        await assertVerificationFailure(
            try await verifier(dns: dns, http: http).verify(
                plcState: state(handle: "alice.3com"),
                expectedDID: did,
                handle: "alice.3com",
                pdsOrigin: "https://pds.example.org"
            )
        )
        let txtNames = await dns.txtNames()
        let requests = await http.requests()
        XCTAssertEqual(txtNames, [])
        XCTAssertEqual(requests, [])
    }

    func testProductionIPv6PolicyRejectsCurrentSpecialPurposeRanges() throws {
        for literal in [
            "2001::1",       // IETF protocol assignments
            "2001:db8::1",   // documentation
            "2002::1",       // 6to4
            "3fff::1",       // documentation
            "3fff:fff::1",   // upper edge of 3fff::/20
        ] {
            let address = try XCTUnwrap(ATHandleIPAddress(literal: literal))
            XCTAssertFalse(address.isPublicInternetAddress, literal)
        }
        XCTAssertTrue(
            try XCTUnwrap(
                ATHandleIPAddress(literal: "2606:4700:4700::1111")
            ).isPublicInternetAddress
        )
        let loopback = try XCTUnwrap(ATHandleIPAddress(literal: "::1"))
        XCTAssertTrue(loopback.isLoopback)
        XCTAssertFalse(loopback.isPublicInternetAddress)
    }

    func testPortableTXTParserCombinesChunksAndRejectsMalformedWireData() throws {
        let response = dnsTXTResponse(chunks: [
            Data("did=".utf8),
            Data(did.utf8),
        ])
        var output = [UInt8](repeating: 0, count: 128)
        let count = response.withUnsafeBufferPointer { input in
            output.withUnsafeMutableBufferPointer { destination in
                swan_at_handle_parse_txt_response(
                    input.baseAddress,
                    input.count,
                    destination.baseAddress,
                    destination.count
                )
            }
        }
        let payload = Data("did=\(did)".utf8)
        XCTAssertEqual(Int(count), payload.count + 2)
        XCTAssertEqual(
            Data(output.prefix(Int(count))),
            Data([UInt8(payload.count >> 8), UInt8(payload.count & 0xff)])
                + payload
        )

        var malformed = response
        malformed[malformed.count - did.utf8.count - 1] = 0xff
        let malformedResult = malformed.withUnsafeBufferPointer { input in
            output.withUnsafeMutableBufferPointer { destination in
                swan_at_handle_parse_txt_response(
                    input.baseAddress,
                    input.count,
                    destination.baseAddress,
                    destination.count
                )
            }
        }
        XCTAssertLessThan(malformedResult, 0)
    }

    func testLaboratoryTestHandleUsesConfiguredLiteralLoopbackOrigin() async throws {
        let loopback = ATHandleIPAddress(literal: "127.0.0.1")!
        let dns = FakeHandleDNS(
            txt: [.success([])],
            addresses: [.success([loopback]), .success([loopback])]
        )
        let http = FakeHandleHTTP([
            .init(
                status: 200,
                body: Data(did.utf8),
                peer: loopback
            ),
        ])
        let policy = try ATHandleResolutionPolicy.laboratory(
            origin: URL(string: "http://127.0.0.1:8080")!
        )
        let verified = try await ATProtocolHandleVerifier(
            policy: policy,
            dns: dns,
            http: http
        ).verify(
            plcState: state(
                handle: "alice.test",
                pds: "http://127.0.0.1:3000"
            ),
            expectedDID: did,
            handle: "alice.test",
            pdsOrigin: "http://127.0.0.1:3000"
        )
        XCTAssertEqual(verified.did, did)
        let requests = await http.requests()
        XCTAssertEqual(
            requests.first?.absoluteString,
            "http://127.0.0.1:8080/.well-known/atproto-did"
        )
    }

    func testDNSMismatchAndAmbiguityOutrankHTTPS() async throws {
        for records in [
            [try txt("did=did:plc:zyxwvutsrqponmlkjihgfedc")],
            [
                try txt("did=\(did)"),
                try txt("did=did:plc:zyxwvutsrqponmlkjihgfedc"),
            ],
            [try txt("did=NOT-A-DID")],
        ] {
            let dns = FakeHandleDNS(txt: [.success(records)], addresses: [])
            let http = FakeHandleHTTP([])
            await assertVerificationFailure(
                try await verifier(dns: dns, http: http).verify(
                    plcState: state(),
                    expectedDID: did,
                    handle: "alice.example.org",
                    pdsOrigin: "https://pds.example.org"
                )
            )
            let requests = await http.requests()
            XCTAssertEqual(requests, [])
        }
    }

    func testHTTPSFallbackAcceptsSmallASCIIWhitespaceAndAnyContentType() async throws {
        let dns = publicDNS(txt: [])
        let http = FakeHandleHTTP([
            .init(
                status: 204,
                headers: ["Content-Type": ["application/octet-stream"]],
                body: Data(" \t\(did)\r\n".utf8),
                peer: publicPeer
            ),
        ])
        let result = try await verifier(dns: dns, http: http).verify(
            plcState: state(),
            expectedDID: did,
            handle: "alice.example.org",
            pdsOrigin: "https://pds.example.org"
        )
        XCTAssertEqual(result.did, did)
    }

    func testHTTPSRedirectRequiresEveryHopToRemainSafe() async throws {
        let dns = FakeHandleDNS(
            txt: [.success([])],
            addresses: [
                .success([publicPeer]), .success([publicPeer]),
                .success([publicPeer]), .success([publicPeer]),
            ]
        )
        let first = URL(string: "https://alice.example.org/.well-known/atproto-did")!
        let second = URL(string: "https://identity.example.net/final")!
        let http = FakeHandleHTTP([
            .init(
                status: 302,
                headers: ["Location": [second.absoluteString]],
                body: Data(),
                peer: publicPeer
            ),
            .init(status: 200, body: Data(did.utf8), peer: publicPeer),
        ])
        _ = try await verifier(dns: dns, http: http).verify(
            plcState: state(),
            expectedDID: did,
            handle: "alice.example.org",
            pdsOrigin: "https://pds.example.org"
        )
        let requests = await http.requests()
        XCTAssertEqual(requests, [first, second])

        let unsafeDNS = publicDNS(txt: [])
        let unsafeHTTP = FakeHandleHTTP([
            .init(
                status: 302,
                headers: ["location": ["http://127.0.0.1:9090/steal"]],
                body: Data(),
                peer: publicPeer
            ),
        ])
        await assertVerificationFailure(
            try await verifier(dns: unsafeDNS, http: unsafeHTTP).verify(
                plcState: state(),
                expectedDID: did,
                handle: "alice.example.org",
                pdsOrigin: "https://pds.example.org"
            )
        )
    }

    func testPrivateReboundAndMissingPeerResponsesFailClosed() async throws {
        let privatePeer = ATHandleIPAddress(literal: "10.0.0.1")!
        let documentationPeer = ATHandleIPAddress(literal: "3fff::1")!
        let cases: [(FakeHandleDNS, FakeHandleHTTP)] = [
            (
                FakeHandleDNS(
                    txt: [.success([])],
                    addresses: [.success([privatePeer])]
                ),
                FakeHandleHTTP([])
            ),
            (
                FakeHandleDNS(
                    txt: [.success([])],
                    addresses: [.success([documentationPeer])]
                ),
                FakeHandleHTTP([])
            ),
            (
                FakeHandleDNS(
                    txt: [.success([])],
                    addresses: [
                        .success([publicPeer]), .success([
                            ATHandleIPAddress(literal: "1.1.1.1")!,
                        ]),
                    ]
                ),
                FakeHandleHTTP([
                    .init(status: 200, body: Data(did.utf8), peer: publicPeer),
                ])
            ),
            (
                publicDNS(txt: []),
                FakeHandleHTTP([
                    .init(status: 200, body: Data(did.utf8), peer: nil),
                ])
            ),
            // A transport that answers for a URL other than the one it was
            // asked for. The guard that catches this used to compare the
            // request URL against itself, so it could not fail; now that the
            // transports report the URL their emitted target denotes, it can,
            // and this is the case that proves the caller still checks.
            (
                publicDNS(txt: []),
                FakeHandleHTTP([
                    .init(
                        status: 200,
                        body: Data(did.utf8),
                        peer: publicPeer,
                        responseURL: URL(string: "https://alice.example.org/other")!
                    ),
                ])
            ),
        ]
        for (dns, http) in cases {
            await assertVerificationFailure(
                try await verifier(dns: dns, http: http).verify(
                    plcState: state(),
                    expectedDID: did,
                    handle: "alice.example.org",
                    pdsOrigin: "https://pds.example.org"
                )
            )
        }
    }

    func testTimeoutAndMalformedHTTPSBodiesFailOpaque() async throws {
        let slowDNS = FakeHandleDNS(
            txt: [.delay(0.25, [])],
            addresses: []
        )
        let start = Date()
        await assertUnavailable(
            try await ATProtocolHandleVerifier(
                policy: try .production(timeout: 0.02),
                dns: slowDNS,
                http: FakeHandleHTTP([])
            ).verify(
                plcState: state(),
                expectedDID: did,
                handle: "alice.example.org",
                pdsOrigin: "https://pds.example.org"
            )
        )
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.15)

        for body in [
            Data(repeating: 0x20, count: 70) + Data(did.utf8),
            Data("DID:PLC:ABCDEFGHIJKLMNOPQRSTUVWX".utf8),
            Data([0xff, 0xfe]),
        ] {
            let dns = publicDNS(txt: [])
            let http = FakeHandleHTTP([
                .init(status: 200, body: body, peer: publicPeer),
            ])
            await assertVerificationFailure(
                try await verifier(dns: dns, http: http).verify(
                    plcState: state(),
                    expectedDID: did,
                    handle: "alice.example.org",
                    pdsOrigin: "https://pds.example.org"
                )
            )
        }
    }

    func testPLCProjectionMustMatchExactlyBeforeAnyResolution() async throws {
        let mutations: [PLCDocumentData] = [
            state(handle: "other.example.org"),
            PLCDocumentData(
                did: did,
                rotationKeys: ["did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"],
                verificationMethods: [:],
                alsoKnownAs: ["at://alice.example.org"],
                services: [
                    "atproto_pds": .init(
                        type: "Other",
                        endpoint: "https://pds.example.org"
                    ),
                ]
            ),
            state(pds: "https://other.example.org"),
        ]
        for state in mutations {
            let dns = FakeHandleDNS(txt: [], addresses: [])
            await assertVerificationFailure(
                try await verifier(dns: dns, http: FakeHandleHTTP([])).verify(
                    plcState: state,
                    expectedDID: did,
                    handle: "alice.example.org",
                    pdsOrigin: "https://pds.example.org"
                )
            )
            let txtNames = await dns.txtNames()
            XCTAssertEqual(txtNames, [])
        }
    }

    private func verifier(
        dns: FakeHandleDNS,
        http: FakeHandleHTTP
    ) -> ATProtocolHandleVerifier {
        ATProtocolHandleVerifier(
            policy: try! .production(),
            dns: dns,
            http: http
        )
    }

    private func publicDNS(
        txt records: [ATHandleTXTRecord]
    ) -> FakeHandleDNS {
        FakeHandleDNS(
            txt: [.success(records)],
            addresses: [.success([publicPeer]), .success([publicPeer])]
        )
    }

    private func state(
        handle: String = "alice.example.org",
        pds: String = "https://pds.example.org"
    ) -> PLCDocumentData {
        PLCDocumentData(
            did: did,
            rotationKeys: [
                "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
            ],
            verificationMethods: [
                "atproto":
                    "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
            ],
            alsoKnownAs: ["at://\(handle)"],
            services: [
                "atproto_pds": .init(
                    type: "AtprotoPersonalDataServer",
                    endpoint: pds
                ),
            ]
        )
    }

    private func dnsTXTResponse(chunks: [Data]) -> [UInt8] {
        var question: [UInt8] = []
        for label in ["_atproto", "alice", "example", "org"] {
            question.append(UInt8(label.utf8.count))
            question.append(contentsOf: label.utf8)
        }
        question.append(0)
        question.append(contentsOf: [0, 16, 0, 1])

        var rdata: [UInt8] = []
        for chunk in chunks {
            precondition(chunk.count <= 255)
            rdata.append(UInt8(chunk.count))
            rdata.append(contentsOf: chunk)
        }
        var response: [UInt8] = [
            0x12, 0x34, 0x81, 0x80,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
        ]
        response.append(contentsOf: question)
        response.append(contentsOf: [
            0xc0, 0x0c,
            0x00, 0x10,
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x3c,
            UInt8(rdata.count >> 8), UInt8(rdata.count & 0xff),
        ])
        response.append(contentsOf: rdata)
        return response
    }

    private func txt(_ value: String) throws -> ATHandleTXTRecord {
        try .init(bytes: Data(value.utf8))
    }

    private func assertVerificationFailure<T>(
        _ expression: @autoclosure () async throws -> T,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await expression()
            XCTFail("expected verification failure", file: file, line: line)
        } catch {
            XCTAssertEqual(
                error as? ATHandleVerificationError,
                .verificationFailed,
                file: file,
                line: line
            )
        }
    }

    private func assertUnavailable<T>(
        _ expression: @autoclosure () async throws -> T,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await expression()
            XCTFail("expected unavailability", file: file, line: line)
        } catch {
            XCTAssertEqual(
                error as? ATHandleVerificationError,
                .unavailable,
                file: file,
                line: line
            )
        }
    }

    // MARK: - Task 10: DNS Admission and Deadline Bounds

    func testHandleDNSAdmissionGateLimitsActiveAndQueuedOperations() async throws {
        let gate = HandleDNSAdmissionGate(maxActive: 8, maxQueued: 128)
        var activeTasks: [Task<Void, Error>] = []
        var queuedTasks: [Task<Void, Error>] = []
        defer {
            for task in activeTasks + queuedTasks { task.cancel() }
        }

        // Fill 8 active slots
        for _ in 0 ..< 8 {
            activeTasks.append(Task {
                try await gate.acquire()
            })
        }
        for task in activeTasks {
            try await task.value
        }
        XCTAssertEqual(gate.activeCount, 8)
        XCTAssertEqual(gate.queuedCount, 0)

        // Fill 128 queued slots
        for _ in 0 ..< 128 {
            queuedTasks.append(Task {
                try await gate.acquire()
            })
        }
        let start = ContinuousClock.now
        while gate.queuedCount < 128, ContinuousClock.now - start < .seconds(2) {
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTAssertEqual(gate.queuedCount, 128)

        // 129th queued request must immediately fail with unavailable
        do {
            try await gate.acquire()
            XCTFail("expected admission failure when queue is full")
        } catch {
            XCTAssertEqual(error as? ATHandleDNSAdmissionError, .saturated)
        }
    }

    func testHandleDNSAdmissionGateCancelledWaitersLeaveQueue() async throws {
        let gate = HandleDNSAdmissionGate(maxActive: 1, maxQueued: 2)

        // Fill 1 active slot
        let activeTask = Task {
            try await gate.acquire()
        }
        try await activeTask.value
        XCTAssertEqual(gate.activeCount, 1)
        XCTAssertEqual(gate.queuedCount, 0)

        // Queue 2 waiters
        let waiter1 = Task { try await gate.acquire() }
        let waiter2 = Task { try await gate.acquire() }
        let startQueue = ContinuousClock.now
        while gate.queuedCount < 2, ContinuousClock.now - startQueue < .seconds(1) {
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTAssertEqual(gate.queuedCount, 2)

        // 3rd waiter fails because queue is full
        do {
            try await gate.acquire()
            XCTFail("expected unavailable")
        } catch {
            XCTAssertEqual(error as? ATHandleDNSAdmissionError, .saturated)
        }

        // Cancel waiter1 -> must leave queue
        waiter1.cancel()
        let startCancel = ContinuousClock.now
        while gate.queuedCount > 1, ContinuousClock.now - startCancel < .seconds(1) {
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTAssertEqual(gate.queuedCount, 1)

        // Now a new waiter can queue
        let waiter3 = Task { try await gate.acquire() }
        let startQueue3 = ContinuousClock.now
        while gate.queuedCount < 2, ContinuousClock.now - startQueue3 < .seconds(1) {
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTAssertEqual(gate.queuedCount, 2)
        waiter2.cancel()
        waiter3.cancel()
        gate.release()
    }

    func testHandleDNSAdmissionGateFailurePathReleasesSlot() async throws {
        let gate = HandleDNSAdmissionGate(maxActive: 1, maxQueued: 2)

        // Acquire slot
        try await gate.acquire()
        XCTAssertEqual(gate.activeCount, 1)

        // Simulate failure in operation -> release slot in defer
        gate.release()
        XCTAssertEqual(gate.activeCount, 0)

        // Next acquire succeeds
        try await gate.acquire()
        XCTAssertEqual(gate.activeCount, 1)
        gate.release()
        XCTAssertEqual(gate.activeCount, 0)
    }

    func testSystemATHandleDNSResolverRejectsWhenGateIsSaturated() async throws {
        let gate = HandleDNSAdmissionGate(maxActive: 1, maxQueued: 0)
        let resolver = SystemATHandleDNSResolver(gate: gate)

        // Saturate gate with 1 active permit
        try await gate.acquire()

        // Next txtRecords and addresses calls via SystemATHandleDNSResolver must fail with .unavailable
        do {
            _ = try await resolver.txtRecords(name: "_atproto.example.com")
            XCTFail("expected unavailable error when gate is saturated")
        } catch {
            XCTAssertEqual(error as? ATHandleDNSAdmissionError, .saturated)
        }

        do {
            _ = try await resolver.addresses(host: "example.com")
            XCTFail("expected unavailable error when gate is saturated")
        } catch {
            XCTAssertEqual(error as? ATHandleDNSAdmissionError, .saturated)
        }

        gate.release()
    }

    func testHandleVerifierMapsSaturatedDNSToUnavailableRatherThanVerificationFailed() async throws {
        let gate = HandleDNSAdmissionGate(maxActive: 1, maxQueued: 0)
        let dns = SystemATHandleDNSResolver(gate: gate)
        let verifier = ATProtocolHandleVerifier(
            policy: try .production(),
            dns: dns,
            http: FakeHandleHTTP([])
        )
        try await gate.acquire()
        defer { gate.release() }

        do {
            _ = try await verifier.verify(
                plcState: state(handle: "alice.example.org"),
                expectedDID: did,
                handle: "alice.example.org",
                pdsOrigin: "https://pds.example.org"
            )
            XCTFail("expected unavailable error")
        } catch let error as ATHandleVerificationError {
            XCTAssertEqual(error, .unavailable, "saturated DNS must yield .unavailable, never .verificationFailed")
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        do {
            _ = try await verifier.resolve(handle: "alice.example.org")
            XCTFail("expected unavailable error")
        } catch let error as ATHandleVerificationError {
            XCTAssertEqual(error, .unavailable, "saturated DNS must yield .unavailable, never .verificationFailed")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }
}

private enum FakeDNSResult<Value: Sendable>: Sendable {
    case success(Value)
    case failure
    case delay(TimeInterval, Value)
}

private actor FakeHandleDNS: ATHandleDNSResolving {
    private var txtResults: [FakeDNSResult<[ATHandleTXTRecord]>]
    private var addressResults: [FakeDNSResult<[ATHandleIPAddress]>]
    private var observedTXTNames: [String] = []

    init(
        txt: [FakeDNSResult<[ATHandleTXTRecord]>],
        addresses: [FakeDNSResult<[ATHandleIPAddress]>]
    ) {
        txtResults = txt
        addressResults = addresses
    }

    func txtRecords(name: String) async throws -> [ATHandleTXTRecord] {
        observedTXTNames.append(name)
        guard !txtResults.isEmpty else {
            throw ATHandleVerificationError.unavailable
        }
        return try await resolve(txtResults.removeFirst())
    }

    func addresses(host _: String) async throws -> [ATHandleIPAddress] {
        guard !addressResults.isEmpty else {
            throw ATHandleVerificationError.unavailable
        }
        return try await resolve(addressResults.removeFirst())
    }

    func txtNames() -> [String] { observedTXTNames }

    private func resolve<Value: Sendable>(
        _ result: FakeDNSResult<Value>
    ) async throws -> Value {
        switch result {
        case let .success(value):
            return value
        case .failure:
            throw ATHandleVerificationError.unavailable
        case let .delay(seconds, value):
            try? await Task.sleep(
                nanoseconds: UInt64(seconds * 1_000_000_000)
            )
            return value
        }
    }
}

private actor FakeHandleHTTP: ATHandleHTTPFetching {
    struct Result: Sendable {
        let status: Int
        var headers: [String: [String]] = [:]
        let body: Data
        let peer: ATHandleIPAddress?
        /// Overrides the URL this fake reports back. Nil echoes the requested
        /// URL, which is what a well-behaved transport does; a value is how a
        /// test drives the verifier's exact-URL guard, which nothing could
        /// reach while the fake always echoed.
        var responseURL: URL?
    }

    private var results: [Result]
    private var observed: [URL] = []

    init(_ results: [Result]) {
        self.results = results
    }

    func get(
        url: URL,
        approvedPeers _: Set<ATHandleIPAddress>,
        timeout _: TimeInterval,
        maximumBodyBytes _: Int
    ) async throws -> ATHandleHTTPResponse {
        observed.append(url)
        guard !results.isEmpty else {
            throw ATHandleVerificationError.unavailable
        }
        let result = results.removeFirst()
        return .init(
            status: result.status,
            headers: result.headers,
            body: result.body,
            responseURL: result.responseURL ?? url,
            connectedPeer: result.peer
        )
    }

    func requests() -> [URL] { observed }
}
