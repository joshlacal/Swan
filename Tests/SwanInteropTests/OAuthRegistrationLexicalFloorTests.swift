import Foundation
import SwanCore
import SwanOAuth
import XCTest

/// The lexical floor at client registration — layer 1, and after §9-D21 the
/// *entire* defence at that layer.
///
/// §9-D21 retires `isIssuableQualified` as a semantic client-metadata gate, so
/// what remains is exactly what upstream has: a well-formed RFC 6749 §3.3
/// scope-token list, plus Swan's documented raw-input budget. Upstream's whole
/// client-metadata scope validator is `OAUTH_SCOPE_REGEXP`
/// (`oauth-types/src/oauth-scope.ts:5-6`, reached via `oauth-client-metadata.ts:36`),
/// which excludes `"` (0x22) and `\` (0x5C).
///
/// **Why these tests exist at the *value* level and not only at the parser.**
/// `OAuthClientMetadata` has three construction paths and only two of them build
/// scopes from a string: the `Decodable` init and the localhost query-string
/// form, both of which run `parseScopes`. The public memberwise initializer
/// takes a `Set<String>` that is already split, so it reaches neither — which
/// left the floor unenforced on that path until it moved into `validate()`, the
/// one funnel every path passes through. A test that only exercised
/// `ScopeToken.isScopeToken` would have passed throughout.
final class OAuthRegistrationLexicalFloorTests: XCTestCase {
    private let clientID = URL(string: "https://client.example/client-metadata.json")!
    private let redirect = URL(string: "https://client.example/callback")!

    private func metadata(scopes: Set<String>) throws -> OAuthClientMetadata {
        try OAuthClientMetadata(
            clientID: clientID,
            redirectURIs: [redirect],
            grantTypes: ["authorization_code"],
            responseTypes: ["code"],
            scopes: scopes,
            dpopBoundAccessTokens: true
        )
    }

    // MARK: the bytes RFC 6749 excludes

    func testRegistrationRejectsAQuoteInAScopeToken() {
        // 0x22. Admitted by the retired `$0 > 0x20 && $0 < 0x7F` check, which is
        // why §4.2 names it specifically.
        XCTAssertThrowsError(try metadata(scopes: ["atproto", "space:x.y.z?skey=a\"b"]))
    }

    func testRegistrationRejectsABackslashInAScopeToken() {
        // 0x5C. Same provenance as the quote: excluded by the RFC so a grant
        // survives being carried inside a quoted string.
        XCTAssertThrowsError(try metadata(scopes: ["atproto", "space:x.y.z?skey=a\\b"]))
    }

    func testTheRejectedBytesAreExactlyTheOnesScopeTokenExcludes() {
        // Ties the value-level floor to the ONE charset definition, so this file
        // cannot drift from `ScopeToken` into a second opinion.
        XCTAssertFalse(ScopeToken.isScopeToken("space:x.y.z?skey=a\"b"))
        XCTAssertFalse(ScopeToken.isScopeToken("space:x.y.z?skey=a\\b"))
        XCTAssertTrue(ScopeToken.isScopeToken("space:x.y.z?skey=ab"))
    }

    // MARK: the floor is lexical ONLY — registration still grants nothing

    func testRegistrationAcceptsASemanticallyMalformedButLexicallyValidScope() throws {
        // §9-D21: registration grants nothing, so an unparseable scope registers
        // fine and is refused later, at PAR, if it is actually requested. If this
        // starts throwing, the retired semantic gate has grown back.
        let malformed = "space:not-an-nsid?authority=notadid&skey=k&action=read"
        XCTAssertTrue(ScopeToken.isScopeToken(malformed))
        XCTAssertNoThrow(try metadata(scopes: ["atproto", malformed]))
    }

    func testRegistrationAcceptsAnUnknownAndAFutureScopeFamily() throws {
        // Upstream holds no dictionary of permission families at registration,
        // and neither does Swan.
        XCTAssertNoThrow(try metadata(scopes: ["atproto", "some.future.family:whatever"]))
    }

    func testRegistrationNoLongerRequiresABaseScope() throws {
        // The `scopes.contains("atproto")` arm was deleted with the rest of the
        // predicate (§9-D21): a base-scope requirement is semantic registration
        // policy, and the floor lives at PAR/admission instead.
        XCTAssertNoThrow(try metadata(scopes: ["space:x.y.z?authority=did:plc:abc&skey=*&action=read"]))
    }

    // MARK: the budget half of layer 1

    func testRegistrationRejectsAnOversizedScopeToken() {
        let oversized = "space:" + String(repeating: "a", count: 1_100)
        XCTAssertGreaterThan(oversized.utf8.count, OAuthScopeBudget.rawInput.bytesPerScope)
        XCTAssertThrowsError(try metadata(scopes: ["atproto", oversized]))
    }

    func testRegistrationAcceptsAScopeAtTheBudgetBoundary() throws {
        // 1024 exactly — the cap is inclusive, and a multi-collection `space:`
        // grant is why it was raised from 256 (§9-D9).
        let atCap = "space:" + String(repeating: "a", count: 1_024 - "space:".utf8.count)
        XCTAssertEqual(atCap.utf8.count, OAuthScopeBudget.rawInput.bytesPerScope)
        XCTAssertNoThrow(try metadata(scopes: [atCap]))
    }

    func testRegistrationRejectsTooManyScopes() {
        let many = Set((0...OAuthScopeBudget.rawInput.scopeCount).map { "space:a.b.c\($0)" })
        XCTAssertGreaterThan(many.count, OAuthScopeBudget.rawInput.scopeCount)
        XCTAssertThrowsError(try metadata(scopes: many))
    }

    func testRegistrationRejectsAnEmptyScopeSet() {
        // `OAUTH_SCOPE_REGEXP` matches a non-empty list, and `parseScopes`
        // already refuses an empty string on the two string paths. The set path
        // has to agree or the floor differs by construction route.
        XCTAssertThrowsError(try metadata(scopes: []))
    }
}
