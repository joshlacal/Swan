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
        let response = try await adapter.submit(.init(subject: .repoRef(did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"), reasonType: "com.atproto.moderation.defs#reasonSpam", reason: "spam", details: "secret details", modTool: .init(name: "swan/account-portal")))
        XCTAssertEqual(response.accepted, true)
        let path = await transport.path
        let body = await transport.body
        XCTAssertEqual(path, "/reports")
        XCTAssertTrue(body.contains("reasonType"))
        XCTAssertTrue(body.contains("com.atproto.admin.defs#repoRef"))
        XCTAssertTrue(body.contains("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"))
        XCTAssertTrue(body.contains("account-portal"))
    }

    func testModerationReportRejectsUnknownReasonAndOversizedReferenceReason() async throws {
        let adapter = try ModerationServiceAdapter(
            transport: TestModerationTransport(), allowedHost: "moderation.example",
            pinnedPeer: "sha256/peer"
        )
        let subject = ModerationSubject.repoRef(did: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
        do {
            _ = try await adapter.submit(.init(subject: subject, reasonType: "example.invalid#reason"))
            XCTFail("unknown reason unexpectedly accepted")
        } catch let error as ModerationServiceAdapterError {
            XCTAssertEqual(error, .invalidReport)
        }
        do {
            _ = try await adapter.submit(.init(
                subject: subject,
                reasonType: "com.atproto.moderation.defs#reasonOther",
                reason: String(repeating: "x", count: 20_001)
            ))
            XCTFail("oversized reason unexpectedly accepted")
        } catch let error as ModerationServiceAdapterError {
            XCTAssertEqual(error, .invalidReport)
        }
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
