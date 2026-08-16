import Foundation
import XCTest
@testable import SwanInterop

final class ModerationServiceAdapterTests: XCTestCase {
    func testModerationReportUsesAllowlistedRouteRedactedBodyAndPinnedPeer() async throws {
        let transport = TestModerationTransport()
        let adapter = try ModerationServiceAdapter(
            transport: transport,
            allowedHost: "moderation.example",
            pinnedPeer: "sha256/peer",
            maximumBodyBytes: 256,
            correlationKeyID: "test-key",
            correlationKeyVersion: 1,
            correlationKey: Data(repeating: 4, count: 32)
        )
        let response = try await adapter.submit(.init(subject: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", reason: "spam", details: "secret details"))
        XCTAssertEqual(response.accepted, true)
        let path = await transport.path
        let body = await transport.body
        XCTAssertEqual(path, "/reports")
        XCTAssertFalse(body.contains("did:plc:"))
        XCTAssertFalse(body.contains("secret details"))
        XCTAssertTrue(body.contains("subjectCorrelation"))
        XCTAssertTrue(body.contains("detailsCorrelation"))
    }
}

private actor TestModerationTransport: ModerationTransport {
    var path = ""
    var body = ""
    func send(_ request: ModerationTransportRequest) async throws -> ModerationTransportResponse {
        self.path = request.path
        self.body = String(decoding: request.body, as: UTF8.self)
        return .init(status: 202, body: Data("{}".utf8), peer: request.pinnedPeer)
    }
}
