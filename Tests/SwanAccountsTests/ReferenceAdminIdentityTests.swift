import Foundation
import XCTest
@testable import SwanAccounts
import SwanStorage
import SwanCore

final class ReferenceAdminIdentityTests: XCTestCase {
    func testPLCUpdateRequiresFreshStepUpAndReturnsSanitizedOperation() async throws {
        let recorder = ReferencePLCUpdateRecorder()
        let policy = RecordingStepUpPolicy()
        let adapter = ReferencePLCIdentityUpdateAdapter(service: recorder, stepUp: policy)
        let result = try await adapter.update(
            .init(accountDID: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", requestID: "r1", sessionID: try .init(rawValue: "session-1")),
            now: Date()
        )
        XCTAssertEqual(result.generation, 2)
        XCTAssertEqual(result.operationCID, "bafyreibbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        let calls = await recorder.calls
        XCTAssertEqual(calls, 1)
        let policyCalls = await policy.calls
        XCTAssertEqual(policyCalls, 1)
    }

    func testPLCUpdateDoesNotCallMutationWhenStepUpPolicyRejects() async throws {
        let recorder = ReferencePLCUpdateRecorder()
        let policy = RecordingStepUpPolicy(shouldFail: true)
        let adapter = ReferencePLCIdentityUpdateAdapter(service: recorder, stepUp: policy)
        do {
            _ = try await adapter.update(.init(accountDID: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", requestID: "r2", sessionID: try .init(rawValue: "session-2")))
            XCTFail("step-up unexpectedly succeeded")
        } catch { }
        let calls = await recorder.calls
        XCTAssertEqual(calls, 0)
    }

    func testAdminLifecycleIsOperatorOnlyAndAudited() async throws {
        let audit = ReferenceAdminAuditRecorder()
        let mutation = RecordingAdminMutation()
        let admin = ReferenceAdminLifecycleService(mutation: mutation, audit: audit)
        let authorization = try OperatorSecretResolver.authorize(environment: ["SWAN_OPERATOR_SECRET": "secret"], secretFile: nil)
        let result = try await admin.suspend(accountDID: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", reason: "abuse", authorization: authorization)
        XCTAssertEqual(result.status, .suspended)
        let events = await audit.events
        XCTAssertEqual(events.count, 1)
        XCTAssertFalse(events[0].contains("abuse"))
    }

    func testAdminDoesNotAuditWhenMutationFails() async throws {
        let audit = ReferenceAdminAuditRecorder()
        let mutation = RecordingAdminMutation(shouldFail: true)
        let admin = ReferenceAdminLifecycleService(mutation: mutation, audit: audit)
        let authorization = try OperatorSecretResolver.authorize(environment: ["SWAN_OPERATOR_SECRET": "secret"], secretFile: nil)
        do {
            _ = try await admin.suspend(accountDID: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", reason: "abuse", authorization: authorization)
            XCTFail("mutation unexpectedly succeeded")
        } catch { }
        let events = await audit.events
        XCTAssertEqual(events.count, 0)
    }
}

private actor ReferencePLCUpdateRecorder: ReferencePLCIdentityUpdateService {
    var calls = 0
    func updatePLCIdentity(accountDID: String, requestID: String, sessionID: ManagementSessionID, minimumStrength: AuthenticationStrength, now: Date) async throws -> ReferencePLCIdentityUpdateResult {
        calls += 1
        return .init(accountDID: accountDID, operationCID: "bafyreibbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", generation: 2)
    }
}

private actor RecordingStepUpPolicy: ReferenceStepUpPolicy {
    var calls = 0
    let shouldFail: Bool
    init(shouldFail: Bool = false) { self.shouldFail = shouldFail }
    func consumeFreshStepUp(sessionID: ManagementSessionID, accountDID: String, requiredStrength: AuthenticationStrength, now: Date) async throws {
        calls += 1
        if shouldFail { throw SwanError.unauthorized("step-up") }
    }
}

private actor RecordingAdminMutation: ReferenceAdminLifecycleMutation {
    let shouldFail: Bool
    init(shouldFail: Bool = false) { self.shouldFail = shouldFail }
    func suspend(accountDID: String, reason: String) async throws -> ReferenceAdminLifecycleResult {
        if shouldFail { throw SwanError.unavailable("mutation") }
        return .init(accountDID: accountDID, status: .suspended)
    }
    func reactivate(accountDID: String) async throws -> ReferenceAdminLifecycleResult {
        if shouldFail { throw SwanError.unavailable("mutation") }
        return .init(accountDID: accountDID, status: .active)
    }
}

private actor ReferenceAdminAuditRecorder: ReferenceAdminAuditSink {
    var events: [String] = []
    func append(_ event: ReferenceAdminAuditEvent) { events.append(event.safeSummary) }
}
