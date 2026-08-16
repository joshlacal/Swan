import XCTest
import Petrel
import SwanAccounts
import SwanStorage
import SwanSpaces
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

    func testLegacyBearerPreservesDistinctTypedGrantAndScope() async throws {
        let store = InMemoryLegacyAuthStore()
        let service = try LegacyAuthService(
            store: store,
            accountResolver: .fixture,
            secretKey: Data(repeating: 7, count: 32),
            tokenIssuer: HMACLegacyTokenIssuer(
                key: Data(repeating: 8, count: 32),
                issuer: "swan.test"
            ),
            managementAuthorizer: LegacyManagementAuthorizer { _, _, _ in true },
            loginAdmission: LegacyLoginAdmission { _ in },
            methodPolicy: .fullAccessV1
        )
        let appPassword = try await service.createAppPassword(
            accountDID: "did:plc:alice",
            name: "client",
            scopes: ["repo:read"],
            managementSessionToken: "m",
            stepUpToken: "s"
        )
        let issued = try await service.createSession(
            identifier: "did:plc:alice",
            password: appPassword.secret
        )
        let authorization = try await SwanLegacyBearerAuthorizer(service: service)
            .authorize(accessToken: issued.accessToken)
        guard case let .accountLegacySession(subject, sessionID, scopes) = authorization else {
            return XCTFail("legacy bearer must not become OAuth or management authorization")
        }
        XCTAssertEqual(subject, "did:plc:alice")
        XCTAssertEqual(sessionID, issued.sessionID)
        XCTAssertEqual(scopes, ["repo:read"])
    }

    func testLegacyAuthAdapterOwnsOnlyGeneratedLocalMethods() {
        XCTAssertEqual(
            SwanLegacyAuthXRPCAdapter.methodNSIDs,
            [
                "com.atproto.server.createSession",
                "com.atproto.server.refreshSession",
                "com.atproto.server.getSession",
                "com.atproto.server.deleteSession",
                "com.atproto.server.getServiceAuth",
                "com.atproto.server.createAppPassword",
                "com.atproto.server.listAppPasswords",
                "com.atproto.server.revokeAppPassword",
            ]
        )
        XCTAssertTrue(
            SwanLegacyAuthXRPCAdapter.methodNSIDs.allSatisfy {
                GeneratedLegacyMethodRegistry.routing[$0] == .local
            }
        )
    }
}
