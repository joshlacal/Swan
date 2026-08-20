import Crypto
import Foundation
import XCTest

@testable import SwanHTTP

final class BrowserPageTests: XCTestCase {
    /// The CSP `style-src` hash is only sound if it covers exactly the bytes
    /// between `<style>` and `</style>` in the page actually served. A build
    /// that regenerated the stylesheet without regenerating the header, or a
    /// page that inlined a second style block, fails here.
    func testInlineStyleMatchesTheDeclaredCSPHash() throws {
        for page in [
            SwanBrowserPages.login(csrf: "token"),
            SwanBrowserPages.consent(
                csrf: "token",
                subject: "did:plc:example",
                clientID: "https://client.example/metadata.json",
                scopes: ["atproto"]
            ),
        ] {
            let blocks = page.components(separatedBy: "<style>")
            XCTAssertEqual(blocks.count, 2, "expected exactly one inline style block")
            let inlined = try XCTUnwrap(blocks.last?.components(separatedBy: "</style>").first)
            let digest = SHA256.hash(data: Data(inlined.utf8))
            XCTAssertEqual(
                SwanBrowserPages.browserStyleCSPSource,
                "'sha256-\(Data(digest).base64EncodedString())'"
            )
            XCTAssertFalse(page.contains("<script"))
            // No remote fetch: the stylesheet is inline, not a CDN reference.
            XCTAssertFalse(page.contains("<link"))
            XCTAssertFalse(page.contains("cdn."))
        }
    }

    func testConsentPageEscapesEveryUntrustedValue() {
        let page = SwanBrowserPages.consent(
            csrf: "\"><script>x</script>",
            subject: "did:plc:<evil>",
            clientID: "https://client.example/\"onerror=\"x",
            scopes: ["atproto", "<img src=x>"]
        )
        XCTAssertFalse(page.contains("<script"))
        XCTAssertFalse(page.contains("<img"))
        XCTAssertFalse(page.contains("<evil>"))
        XCTAssertTrue(page.contains("did:plc:&lt;evil&gt;"))
        XCTAssertTrue(page.contains("value=\"&quot;&gt;&lt;script&gt;"))
    }

    func testLoginPageCarriesTheCSRFTokenAndCredentialFields() {
        let page = SwanBrowserPages.login(csrf: "csrf-token")
        XCTAssertTrue(page.contains("value=\"csrf-token\""))
        XCTAssertTrue(page.contains("name=\"handle\""))
        XCTAssertTrue(page.contains("name=\"password\""))
        XCTAssertTrue(page.contains("action=\"/oauth/authorize\""))
    }
}
