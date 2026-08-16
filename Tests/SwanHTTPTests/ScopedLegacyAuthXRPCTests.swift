import XCTest
import Petrel
import SwanAccounts
@testable import SwanHTTP

final class ScopedLegacyAuthXRPCTests: XCTestCase {
    func testCreateSessionAdapterUsesPinnedWireFields() async throws {
        let store = InMemoryLegacyAuthStore()
        let service = try LegacyAuthService(store: store, accountResolver: .fixture)
        let adapter = SwanLegacyAuthXRPCAdapter(service: service)
        let created = try await service.createAppPassword(accountDID: "did:plc:alice", name: "client", scopes: ["repo:read"])
        let output = try await adapter.createSession(.init(identifier: "did:plc:alice", password: created.secret))
        XCTAssertEqual(output.did.description, "did:plc:alice")
        XCTAssertEqual(output.handle.value, "alice.test")
        XCTAssertFalse(output.accessJwt.isEmpty)
        XCTAssertFalse(output.refreshJwt.isEmpty)
    }
}
