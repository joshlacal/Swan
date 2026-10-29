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
        XCTAssertEqual(PermissionedData0016.profileID, "permissioned-data-0016-2026-10-22")
        XCTAssertEqual(methods.count, 28)
        XCTAssertEqual(Set(methods.map(\.nsid)).count, methods.count)
        // October 22 (reference ac0c9f15, atproto#5705): getRepo serves a STAR
        // archive as application/octet-stream instead of a CAR, and the
        // space-credential reads declare BadSpaceMac for Atproto-Space-Want-Mac.
        XCTAssertTrue(methods.contains {
            $0.nsid == "com.atproto.space.getRepo" && $0.kind == .query
                && $0.outputEncoding == "application/octet-stream"
                && $0.declaredErrors == [
                    "BadSpaceMac", "SpaceNotFound", "RepoNotFound", "RepoTakendown", "RepoSuspended", "RepoDeactivated",
                ]
        })
        XCTAssertFalse(methods.contains { $0.outputEncoding == "application/vnd.ipld.car" })
        for nsid in ["com.atproto.space.getLatestCommit", "com.atproto.space.getRecord", "com.atproto.space.listRepoOps"] {
            XCTAssertTrue(methods.contains { $0.nsid == nsid && $0.declaredErrors.first == "BadSpaceMac" }, nsid)
        }
        XCTAssertTrue(methods.contains { $0.nsid == "com.atproto.space.getSpaceCredential" })
        XCTAssertTrue(methods.contains { $0.nsid == "com.atproto.simplespace.updateSpace" })
        XCTAssertTrue(methods.contains {
            $0.nsid == "com.atproto.space.notifyCredentialRevoked" && $0.kind == .procedure
                && $0.outputEncoding == nil && $0.declaredErrors.isEmpty
        })
        XCTAssertTrue(methods.contains {
            $0.nsid == "com.atproto.space.notifyWrite" && $0.declaredErrors == ["SpaceNotFound", "FutureRev"]
        })
    }
}

