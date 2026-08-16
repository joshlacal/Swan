import Foundation
import XCTest
@testable import SwanAccounts

final class ReferenceAdminIdentityTests: XCTestCase {
    func testPLCUpdateRequiresFreshStepUpAndReturnsSanitizedOperation() async throws {
        let recorder = ReferencePLCUpdateRecorder()
        let adapter = ReferencePLCIdentityUpdateAdapter(service: recorder)
        let result = try await adapter.update(
            .init(accountDID: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", requestID: "r1", stepUp: .init(receiptDigest: Data(repeating: 1, count: 32), expiresAt: Date().addingTimeInterval(60))),
            now: Date()
        )
        XCTAssertEqual(result.generation, 2)
        XCTAssertEqual(result.operationCID, "bafyreibbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        let calls = await recorder.calls
        XCTAssertEqual(calls, 1)
    }

    func testAdminLifecycleIsOperatorOnlyAndAudited() async throws {
        let audit = ReferenceAdminAuditRecorder()
        let admin = ReferenceAdminLifecycleService(audit: audit)
        let authorization = referenceAdminAuthorizationForTesting()
        let result = try await admin.suspend(accountDID: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", reason: "abuse", authorization: authorization)
        XCTAssertEqual(result.status, .suspended)
        let events = await audit.events
        XCTAssertEqual(events.count, 1)
        XCTAssertFalse(events[0].contains("abuse"))
    }
}

private actor ReferencePLCUpdateRecorder: ReferencePLCIdentityUpdateService {
    var calls = 0
    func updatePLCIdentity(accountDID: String, requestID: String, stepUp: ReferenceStepUpReceipt, now: Date) async throws -> ReferencePLCIdentityUpdateResult {
        calls += 1
        return .init(accountDID: accountDID, operationCID: "bafyreibbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", generation: 2)
    }
}

private actor ReferenceAdminAuditRecorder: ReferenceAdminAuditSink {
    var events: [String] = []
    func append(_ event: ReferenceAdminAuditEvent) { events.append(event.safeSummary) }
}
