import Foundation
import XCTest
@testable import SwanAccountExport
@testable import SwanStorage

final class SwanIdentitySnapshotTests: XCTestCase {
    func testRoundTripAndPLCArchiveCompatibility() throws {
        let binding = try IdentityBinding(
            accountDID: "did:plc:abcdefghijklmnopqrstuvwx", identityDID: "did:web:example.com",
            method: .didWeb, handle: "alice.example",
            documentDigest: Data(repeating: 1, count: 32),
            claimReceiptDigest: Data(repeating: 2, count: 32), reservedKeyID: "#atproto"
        )
        let snapshot = try SwanIdentitySnapshot(binding: binding, history: [])
        XCTAssertEqual(try SwanIdentitySnapshot.decode(snapshot.encoded()), snapshot)
        XCTAssertEqual(SwanIdentitySnapshot.plcArchiveCompatibility(Data("plc".utf8)), Data("plc".utf8))
    }
}
