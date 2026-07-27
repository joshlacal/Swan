import CATHandleDNS
import Foundation
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
            responseURL: url,
            connectedPeer: result.peer
        )
    }

    func requests() -> [URL] { observed }
}
