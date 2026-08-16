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
        let response = try await adapter.submit(.init(subject: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", reason: "spam", details: "secret details"))
        XCTAssertEqual(response.accepted, true)
        let path = await transport.path
        let body = await transport.body
        XCTAssertEqual(path, "/reports")
        XCTAssertFalse(body.contains("did:plc:"))
        XCTAssertFalse(body.contains("secret details"))
    }
}

private actor TestModerationTransport: ModerationTransport {
    var path = ""
    var body = ""
    func send(host: String, peer: String, path: String, body: Data, maximumResponseBytes: Int) async throws -> ModerationTransportResponse {
        self.path = path
        self.body = String(decoding: body, as: UTF8.self)
        return .init(status: 202, body: Data("{}".utf8), peer: peer)
    }
}
