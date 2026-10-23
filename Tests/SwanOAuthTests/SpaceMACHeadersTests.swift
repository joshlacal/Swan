import Foundation
import SwanOAuth
import XCTest

final class SpaceMACHeadersTests: XCTestCase {
    func testRequestRoundTripAndStructuredFieldTypes() throws {
        let key = "did:key:zDnaTest"
        let header = try SpaceMACHeaders.formatWantMAC(keyShare: key, type: .repository)
        XCTAssertEqual(header, "type=\"atproto-space-repo\", ver=1, key_share=\"did:key:zDnaTest\"")
        XCTAssertEqual(try SpaceMACHeaders.parseWantMAC(header, type: .repository).keyShare, key)
        XCTAssertThrowsError(try SpaceMACHeaders.parseWantMAC(header, type: .record))
        for bad in [nil, "", "type=atproto-space-repo, ver=1, key_share=\"x\"", "type=\"atproto-space-repo\", ver=\"1\", key_share=\"x\"", "type=\"atproto-space-repo\", ver=2, key_share=\"x\"", "type=\"atproto-space-repo\", ver=1, key_share=x", "type=\"atproto-space-repo\", ver=1, key_share=\"x\", other=(1)"] as [String?] {
            XCTAssertThrowsError(try SpaceMACHeaders.parseWantMAC(bad, type: .repository)) {
                XCTAssertEqual($0 as? SpaceMACHeaders.HeaderError, .badSpaceMAC)
            }
        }
    }

    func testResponseUsesPaddedBase64AndRequires32Bytes() throws {
        let mac = Data(repeating: 0, count: 32)
        let header = try SpaceMACHeaders.formatMAC(mac, type: .record)
        XCTAssertTrue(header.hasSuffix("=:"))
        XCTAssertEqual(try SpaceMACHeaders.parseMAC(header, type: .record), mac)
        XCTAssertEqual(try SpaceMACHeaders.parseMAC(header.replacingOccurrences(of: "=:", with: ":"), type: .record), mac)
        XCTAssertThrowsError(try SpaceMACHeaders.parseMAC(header, type: .repository))
        XCTAssertThrowsError(try SpaceMACHeaders.formatMAC(Data(repeating: 0, count: 31), type: .record))
        XCTAssertThrowsError(try SpaceMACHeaders.parseMAC("type=\"atproto-space-record\", ver=1, mac=:AA==:", type: .record))
        XCTAssertThrowsError(try SpaceMACHeaders.parseMAC("type=\"atproto-space-record\", ver=1, mac=\"invalid\"", type: .record))
    }

    func testParametersAndOrdinaryExtensionFieldsMatchStructuredFieldSemantics() throws {
        let header = "type=\"atproto-space-repo\";p=1, ver=1, key_share=\"did:key:x\";q, ext=?1"
        XCTAssertEqual(try SpaceMACHeaders.parseWantMAC(header, type: .repository).keyShare, "did:key:x")
        XCTAssertThrowsError(try SpaceMACHeaders.formatWantMAC(keyShare: "bad\r\nheader", type: .repository))
        XCTAssertThrowsError(try SpaceMACHeaders.parseWantMAC(String(repeating: "a", count: 8_193), type: .repository))
    }
}
