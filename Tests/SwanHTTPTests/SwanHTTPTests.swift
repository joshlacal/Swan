import Foundation
import HummingbirdTesting
import Logging
import XCTest
@testable import SwanCore
@testable import SwanHTTP
import SwanOAuth
import SwanSQLite

final class SwanHTTPTests: XCTestCase {
    func testRouterBuildsBeforeApplication() async throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "SwanHTTPTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let profile = try ProtocolProfile(data: Data("""
        {"id":"permissioned-data-test","proposalCommit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","referenceImplementationCommit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","petrelGeneratorCommit":"cccccccccccccccccccccccccccccccccccccccc","petrelCommit":"dddddddddddddddddddddddddddddddddddddddd","migrationCompatibility":"test","crypto":{"lthashBytes":2048,"lthashHash":"BLAKE3-XOF","commitmentHash":"SHA-256","contentBinding":"HMAC-SHA-256"},"permissionedDataIsEncrypted":false,"oplogRetention":1,"endpoints":[]}
        """.utf8))
        let controlDatabase = try await SQLiteControlDatabase(dataDirectory: root)
        let runtime = try SwanOAuthRuntime(
            controlStore: controlDatabase,
            serverKey: Data(repeating: 0x71, count: 32)
        )
        let server = SwanHTTPServer(profile: profile, oauthRuntime: runtime)
        let app = server.buildApplication(logger: Logger(label: "SwanHTTPTests"))
        try await app.test(.router) { client in
            for path in [
                "/.well-known/oauth-protected-resource",
                "/.well-known/oauth-authorization-server",
                "/oauth/authorize",
                "/xrpc/com.atproto.space.getRecord",
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
        }
        try await controlDatabase.close()
    }
}
