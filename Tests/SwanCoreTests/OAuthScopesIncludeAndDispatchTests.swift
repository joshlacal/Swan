import Foundation
import Testing
@testable import SwanCore

/// `include:` (Phase 1 only, §9-D4) and the `AtprotoScope` dispatcher (§4.7).
/// Vectors copied inline from
/// docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §5.7.1, §4.7.
@Suite("include: family (Phase 1) and the AtprotoScope dispatcher")
struct OAuthScopesIncludeAndDispatchTests {
    // MARK: include (§5.7.1)

    @Test
    func includeParsesPositionalNsidWithNoAud() throws {
        let scope = try IncludeScope.parse("include:com.example.bar")
        #expect(scope.nsid == "com.example.bar")
        #expect(scope.aud == nil)
    }

    @Test
    func includeParsesAudInBothRawAndPercentEncodedForm() throws {
        let a = try IncludeScope.parse("include:com.example.baz?aud=did:web:example.com%23my_service")
        #expect(a.aud == .service("did:web:example.com#my_service"))
        // A bare `#` in a query string is a literal, not a fragment delimiter.
        let b = try IncludeScope.parse("include:com.example.baz?aud=did:web:example.com#my_service")
        #expect(b.aud == .service("did:web:example.com#my_service"))
    }

    @Test
    func includeAcceptsNamedFormOfThePositionalKeyInAnyOrder() throws {
        let a = try IncludeScope.parse("include?nsid=com.example.baz")
        #expect(a.nsid == "com.example.baz")
        let b = try IncludeScope.parse("include?aud=did:web:example.com%23my_service&nsid=com.example.baz")
        #expect(b.nsid == "com.example.baz" && b.aud == .service("did:web:example.com#my_service"))
    }

    @Test
    func includeRejectsAllSeventeenUpstreamVectors() {
        // include-scope.test.ts:66-87 (18 array entries, two duplicated -> 17 distinct)
        let rejects = [
            "", "repo:com.example.baz", "include", "include#", "include:", "include:#", "include:&",
            "include:com..example", "include:com", "include:com.example", "include:9com.example.foo",
            "include:com.example.-bar", "include:invalid^nsid", "include:nsid",
            "include:com.example.baz?aud=", "include:com.example.baz?aud=did:web:example.com",
            "include:com.example.baz?aud=invalid^did",
        ]
        #expect(rejects.count == 17)
        for scope in rejects {
            #expect(throws: ScopeParseError.self) { try IncludeScope.parse(scope) }
        }
    }

    @Test
    func includeFormat() throws {
        #expect(try IncludeScope(nsid: "com.example.foo").canonicalScopeString() == "include:com.example.foo")
        #expect(try IncludeScope(nsid: "com.example.foo", aud: .service("did:web:example.com#my_service"))
            .canonicalScopeString() == "include:com.example.foo?aud=did:web:example.com%23my_service")
    }

    // MARK: dispatcher (§4.7)

    @Test
    func dispatcherRoutesTransitionAndAtprotoLiteralsWithoutFamilyLookup() throws {
        #expect(try AtprotoScope.parse("atproto") == .atproto)
        #expect(try AtprotoScope.parse("transition:email") == .transitionEmail)
        #expect(try AtprotoScope.parse("transition:generic") == .transitionGeneric)
        #expect(try AtprotoScope.parse("transition:chat.bsky") == .transitionChatBsky)
    }

    @Test
    func dispatcherRoutesEachPrefixToItsFamily() throws {
        guard case .account = try AtprotoScope.parse("account:email") else { Issue.record("expected .account"); return }
        guard case .blob = try AtprotoScope.parse("blob:image/png") else { Issue.record("expected .blob"); return }
        guard case .identity = try AtprotoScope.parse("identity:handle") else { Issue.record("expected .identity"); return }
        guard case .include = try AtprotoScope.parse("include:com.example.foo") else { Issue.record("expected .include"); return }
        guard case .repo = try AtprotoScope.parse("repo:com.example.foo") else { Issue.record("expected .repo"); return }
        guard case .rpc = try AtprotoScope.parse("rpc:com.example.method?aud=*") else { Issue.record("expected .rpc"); return }
        guard case .space = try AtprotoScope.parse("space:com.example.type") else { Issue.record("expected .space"); return }
    }

    @Test
    func dispatcherRejectsUnknownPrefix() {
        #expect(throws: ScopeParseError.self) { try AtprotoScope.parse("openid") }
        #expect(throws: ScopeParseError.self) { try AtprotoScope.parse("nonsense:whatever") }
    }

    @Test
    func dispatcherPrefixesAreDisjointSoSuperstringsDoNotMisroute() {
        // §4.4's isScopeString guarantee, exercised through the dispatcher: a
        // prefix that merely starts with a known prefix must not be misrouted
        // or silently accepted.
        #expect(throws: ScopeParseError.self) { try AtprotoScope.parse("identityfoo:bar") }
    }

    @Test
    func dispatcherCanonicalScopeStringRoundTripsEveryCase() throws {
        for scope in ["atproto", "transition:email", "transition:generic", "transition:chat.bsky",
                      "account:email", "blob:image/png", "identity:handle", "include:com.example.foo",
                      "repo:com.example.foo", "rpc:com.example.method?aud=*", "space:com.example.type"] {
            let parsed = try AtprotoScope.parse(scope)
            #expect(try parsed.canonicalScopeString() == scope)
        }
    }
}
