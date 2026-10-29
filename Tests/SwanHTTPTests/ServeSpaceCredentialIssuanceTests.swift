import Foundation
import SwanOAuth
import SwanSpaces
@testable import swan
import XCTest

/// SWAN-AUTH-5: `swan serve` issues 60-second credentials only for
/// conversation spaces. Enabling the conversation policy leaves every other
/// space on the authority's default lifetime.
final class ServeSpaceCredentialIssuanceTests: XCTestCase {
    private static let authority = "did:plc:abcdefghijklmnopqrstuvwx"

    func testConversationPolicyShortensOnlyConversationCredentials() throws {
        let conversation = try SpaceURI(
            authority: Self.authority,
            spaceType: "blue.catbird.labyrinth.conversation",
            skey: UUID().uuidString.lowercased()
        )
        let bookmarks = try SpaceURI(authority: Self.authority, spaceType: "app.bsky.bookmarks", skey: "saved")
        let defaultLifetime = DurableSpaceCredentialAuthority.Configuration.defaultLifetime

        let enabled = try SwanCommand.Serve.spaceCredentialIssuance(conversationPolicyEnabled: true)
        XCTAssertEqual(enabled.lifetime(for: conversation), 60)
        XCTAssertEqual(enabled.lifetime(for: bookmarks), defaultLifetime)

        let disabled = try SwanCommand.Serve.spaceCredentialIssuance(conversationPolicyEnabled: false)
        XCTAssertEqual(disabled.lifetime(for: conversation), defaultLifetime)
        XCTAssertEqual(disabled.lifetime(for: bookmarks), defaultLifetime)
    }
}
