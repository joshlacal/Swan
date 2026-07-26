import Foundation
import XCTest
@testable import SwanCore
@testable import SwanHTTP

final class SwanHTTPTests: XCTestCase {
    func testRouterBuildsBeforeApplication() throws {
        let profile = try ProtocolProfile(data: Data("""
        {"id":"permissioned-data-test","proposalCommit":"a","referenceImplementationCommit":"b","petrelCommit":"c","migrationCompatibility":"test","crypto":{"lthashBytes":2048,"lthashHash":"BLAKE3-XOF","commitmentHash":"SHA-256","contentBinding":"HMAC-SHA-256"},"permissionedDataIsEncrypted":false,"oplogRetention":1,"endpoints":[]}
        """.utf8))
        let server = SwanHTTPServer(profile: profile)
        _ = server.buildRouter()
    }
}
