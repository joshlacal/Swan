import Crypto
import Foundation
import XCTest
@testable import SwanCore
@testable import SwanSpacesWire

final class SwanCoreTests: XCTestCase {
    func testPinnedProfileLoadsAndEnforcesLtHashSize() throws {
        let file = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appending(path: "Profiles/permissioned-data-0016-2026-07-03.json")
        let profile = try ProtocolProfile.load(from: file)
        XCTAssertEqual(profile.id, "permissioned-data-0016-2026-07-03")
        XCTAssertEqual(profile.crypto.lthashBytes, 2048)
        XCTAssertFalse(profile.permissionedDataIsEncrypted)
    }

    func testSensitiveValueIsNeverDescribed() {
        XCTAssertEqual(Sensitive("bearer-token").description, "[redacted]")
    }

    func testBootstrapWireRegistryCoversEveryPinnedOperation() {
        let methods = PermissionedData0016.methods
        XCTAssertEqual(methods.count, 27)
        XCTAssertEqual(Set(methods.map(\.nsid)).count, methods.count)
        XCTAssertTrue(methods.contains { $0.nsid == "com.atproto.space.getRepo" && $0.outputEncoding == "application/vnd.ipld.car" })
        XCTAssertTrue(methods.contains { $0.nsid == "com.atproto.space.getSpaceCredential" })
        XCTAssertTrue(methods.contains { $0.nsid == "com.atproto.simplespace.updateSpace" })
    }
}

