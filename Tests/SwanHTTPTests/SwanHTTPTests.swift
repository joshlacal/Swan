import Foundation
import Hummingbird
import HummingbirdTesting
import Logging
import XCTest
@testable import SwanCore
@testable import SwanHTTP
import SwanOAuth
import SwanSQLite
import SwanSpacesWire

final class SwanHTTPTests: XCTestCase {
    func testProfileAndGeneratedWireHaveTheSamePermissionedCoverage() throws {
        let profile = try loadPinnedProfile()
        let generated = PermissionedData0016.methods

        XCTAssertEqual(profile.id, PermissionedData0016.profileID)
        XCTAssertEqual(profile.endpoints.count, 25)
        XCTAssertEqual(profile.endpoints, generated.map(\.nsid))
        XCTAssertEqual(Set(profile.endpoints).count, profile.endpoints.count)
    }

    func testEveryPinnedPermissionedEndpointIsMethodCorrectAndFailClosed() async throws {
        let profile = try loadPinnedProfile()
        let (server, controlDatabase, root) = try await makeServer(profile: profile)
        defer { try? FileManager.default.removeItem(at: root) }
        defer { Task { try? await controlDatabase.close() } }

        let app = server.buildApplication(logger: Logger(label: "SwanHTTPTests"))
        try await app.test(.router) { client in
            for descriptor in PermissionedData0016.methods {
                let path = "/xrpc/\(descriptor.nsid)"
                let method = httpMethod(for: descriptor)
                try await client.execute(uri: path, method: method) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable, "\(method.rawValue) \(path)")
                }

                let wrongMethod: HTTPRequest.Method = method == .get ? .post : .get
                try await client.execute(uri: path, method: wrongMethod) { response in
                    XCTAssertEqual(response.status, .notFound, "\(wrongMethod.rawValue) \(path)")
                }
            }
        }
        try await controlDatabase.close()
    }

    func testUnknownPermissionedMethodsAreNotPublicFallbacks() async throws {
        let profile = try loadPinnedProfile()
        let (server, controlDatabase, root) = try await makeServer(profile: profile)
        defer { try? FileManager.default.removeItem(at: root) }
        defer { Task { try? await controlDatabase.close() } }

        let app = server.buildApplication(logger: Logger(label: "SwanHTTPTests"))
        try await app.test(.router) { client in
            let methods: [HTTPRequest.Method] = [
                .get, .head, .post, .put, .patch, .delete, .options, .connect, .trace,
            ]
            for path in [
                "/xrpc/com.atproto.space.unpinnedMethod",
                "/xrpc/com.atproto.simplespace.unpinnedMethod",
            ] {
                for method in methods {
                    try await client.execute(uri: path, method: method) { response in
                        XCTAssertEqual(response.status, .notFound, "\(method.rawValue) \(path)")
                    }
                }
            }
        }
        try await controlDatabase.close()
    }

    func testHealthDescribeServerAndOAuthRemainIsolated() async throws {
        let profile = try loadPinnedProfile()
        let (server, controlDatabase, root) = try await makeServer(profile: profile)
        defer { try? FileManager.default.removeItem(at: root) }
        defer { Task { try? await controlDatabase.close() } }

        let app = server.buildApplication(logger: Logger(label: "SwanHTTPTests"))
        try await app.test(.router) { client in
            for path in [
                "/.well-known/oauth-protected-resource",
                "/.well-known/oauth-authorization-server",
                "/oauth/authorize",
            ] {
                try await client.execute(uri: path, method: .get) { response in
                    XCTAssertEqual(response.status, .serviceUnavailable)
                }
            }
            for path in ["/oauth/par", "/oauth/token", "/oauth/revoke"] {
                try await client.execute(uri: path, method: .post) { response in
                    XCTAssertEqual(response.status, .notFound)
                }
            }
            for path in ["/health", "/xrpc/com.atproto.server.describeServer"] {
                try await client.execute(uri: path, method: .get) { response in
                    XCTAssertEqual(response.status, .ok)
                }
            }
        }
        try await controlDatabase.close()
    }

    private func loadPinnedProfile() throws -> ProtocolProfile {
        try ProtocolProfile.load(from: packageRoot()
            .appending(path: "Profiles/permissioned-data-0016-2026-07-03.json"))
    }

    private func makeServer(profile: ProtocolProfile) async throws -> (SwanHTTPServer, SQLiteControlDatabase, URL) {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanHTTPTests-\(UUID().uuidString)")
        let controlDatabase = try await SQLiteControlDatabase(dataDirectory: root)
        let runtime = try SwanOAuthRuntime(
            controlStore: controlDatabase,
            serverKey: Data(repeating: 0x71, count: 32)
        )
        return (SwanHTTPServer(profile: profile, oauthRuntime: runtime), controlDatabase, root)
    }

    private func packageRoot() -> URL {
        URL(filePath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

}

private func httpMethod(for descriptor: XRPCMethodDescriptor) -> HTTPRequest.Method {
    switch descriptor.kind {
    case .query, .subscription:
        .get
    case .procedure:
        .post
    }
}
