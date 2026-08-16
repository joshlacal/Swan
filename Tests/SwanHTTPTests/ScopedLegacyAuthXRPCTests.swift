import XCTest
import Petrel
import SwanAccounts
import SwanStorage
@testable import SwanHTTP

final class ScopedLegacyAuthXRPCTests: XCTestCase {
    func testCreateSessionAdapterUsesPinnedWireFields() async throws {
        let store = InMemoryLegacyAuthStore()
        let service = try LegacyAuthService(store: store, accountResolver: .fixture, secretKey: Data(repeating: 7, count: 32), tokenIssuer: HMACLegacyTokenIssuer(key: Data(repeating: 8, count: 32), issuer: "swan.test"), managementAuthorizer: LegacyManagementAuthorizer { _, _, _ in true }, loginAdmission: LegacyLoginAdmission { _ in }, methodPolicy: DeclaredMethodScopePolicy.fullAccessV1)
        let adapter = SwanLegacyAuthXRPCAdapter(service: service)
        let created = try await service.createAppPassword(accountDID: "did:plc:alice", name: "client", scopes: ["repo:read"], managementSessionToken: "m", stepUpToken: "s")
        let output = try await adapter.createSession(.init(identifier: "did:plc:alice", password: created.secret))
        XCTAssertEqual(output.did.description, "did:plc:alice")
        XCTAssertEqual(output.handle.value, "alice.test")
        XCTAssertFalse(output.accessJwt.isEmpty)
        XCTAssertFalse(output.refreshJwt.isEmpty)
    }
}
