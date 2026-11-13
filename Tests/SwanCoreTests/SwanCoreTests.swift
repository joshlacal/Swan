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
        XCTAssertEqual(PermissionedData0016.profileID, "permissioned-data-0016-2026-11-12")
        XCTAssertEqual(methods.count, 32)
        XCTAssertEqual(Set(methods.map(\.nsid)).count, methods.count)
        // November 12 (reference d4def6e9): STAR archives use the DASL media
        // type and space-credential reads declare InvalidSpaceMac for the
        // RFC 9421 response-MAC profile.
        XCTAssertTrue(methods.contains {
            $0.nsid == "com.atproto.space.getRepo" && $0.kind == .query
                && $0.outputEncoding == "application/vnd.dasl.star"
                && $0.declaredErrors == [
                    "InvalidSpaceMac", "SpaceNotFound", "RepoNotFound", "RepoTakendown", "RepoSuspended", "RepoDeactivated",
                ]
        })
        XCTAssertFalse(methods.contains { $0.outputEncoding == "application/vnd.ipld.car" })
        for nsid in ["com.atproto.space.getLatestCommit", "com.atproto.space.getRecord", "com.atproto.space.listRepoOps"] {
            XCTAssertTrue(methods.contains { $0.nsid == nsid && $0.declaredErrors.first == "InvalidSpaceMac" }, nsid)
        }
        XCTAssertTrue(methods.contains { $0.nsid == "com.atproto.space.authorizeSpaceSync" })
        XCTAssertTrue(methods.contains { $0.nsid == "com.atproto.space.updateSpace" })
        XCTAssertTrue(methods.contains {
            $0.nsid == "com.atproto.space.notifyCredentialsRevoked" && $0.kind == .procedure
                && $0.outputEncoding == nil && $0.declaredErrors.isEmpty
        })
        XCTAssertTrue(methods.contains {
            $0.nsid == "com.atproto.space.notifyRepoUpdate" && $0.declaredErrors == ["SpaceNotFound", "FutureRev"]
        })
    }
}

