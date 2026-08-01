import Foundation
import SwanInterop
import XCTest

final class PermissionedRemoteReplicaHTTPProviderFaultTests: XCTestCase {
    func testCorruptLastByteFaultChangesOnlyTheFinalByte() throws {
        let directory = try FileManager.default.url(
            for: .itemReplacementDirectory,
            in: .userDomainMask,
            appropriateFor: FileManager.default.temporaryDirectory,
            create: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appending(path: "recovery.car")
        let original = Data([0x01, 0x02, 0x03, 0x04])
        try original.write(to: file)

        try PermissionedRemoteReplicaSourceFault.corruptLastByte.apply(to: file)

        XCTAssertEqual(try Data(contentsOf: file), Data([0x01, 0x02, 0x03, 0x05]))
    }

    func testCorruptLastByteFaultRejectsAnEmptyCAR() throws {
        let directory = try FileManager.default.url(
            for: .itemReplacementDirectory,
            in: .userDomainMask,
            appropriateFor: FileManager.default.temporaryDirectory,
            create: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appending(path: "empty.car")
        try Data().write(to: file)

        XCTAssertThrowsError(
            try PermissionedRemoteReplicaSourceFault.corruptLastByte.apply(to: file)
        )
    }
}
