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
            maximumBodyBytes: 256
        )
        let response = try await adapter.submit(.init(subject: .repoRef(did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"), reasonType: "com.atproto.moderation.defs#reasonSpam", reason: "spam", details: "secret details"))
        XCTAssertEqual(response.accepted, true)
        let path = await transport.path
        let body = await transport.body
        XCTAssertEqual(path, "/reports")
        XCTAssertTrue(body.contains("reasonType"))
        XCTAssertTrue(body.contains("com.atproto.admin.defs#repoRef"))
        XCTAssertTrue(body.contains("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"))
    }
}

private actor TestModerationTransport: ModerationTransport {
    var path = ""
    var body = ""
    func send(_ request: ModerationTransportRequest) async throws -> ModerationTransportResponse {
        self.path = request.path
        self.body = String(decoding: request.body, as: UTF8.self)
        return .init(status: 202, body: Data("{\"id\":1,\"reasonType\":\"com.atproto.moderation.defs#reasonSpam\",\"subject\":{\"$type\":\"com.atproto.admin.defs#repoRef\",\"did\":\"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa\"},\"reason\":\"spam\",\"reportedBy\":\"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb\",\"createdAt\":\"2026-08-16T00:00:00Z\"}".utf8), peer: request.pinnedPeer)
    }
}
