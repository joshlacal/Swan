import Foundation
import Testing

@testable import SwanHTTP

/// Lane 1's `AtprotoScope` / `SpacePermission` (Sources/SwanCore/OAuthScopes,
/// spec §4.7) had not landed when this file was written, so these tests
/// exercise `ConsentScope`/`ScopeDescription` directly — both the bridge
/// parser (`ConsentScope.classify`, driven by raw scope strings, matching
/// what the two consent call sites actually have today) and the renderer
/// fed pre-built `ConsentScope` values (a stand-in for what
/// `AtprotoScope.parse` will hand it once wired).
@Suite("ScopeDescription")
struct ScopeDescriptionTests {

    // MARK: - ConsentScope.classify

    @Test("atproto and the three transition scopes classify by exact match")
    func classifiesStaticScopes() {
        #expect(ConsentScope.classify("atproto") == .atproto)
        #expect(ConsentScope.classify("transition:email") == .transitionEmail)
        #expect(ConsentScope.classify("transition:generic") == .transitionGeneric)
        #expect(ConsentScope.classify("transition:chat.bsky") == .transitionChatBsky)
    }

    @Test("account: positional form with default action")
    func classifiesAccountDefault() {
        #expect(ConsentScope.classify("account:email") == .account(attr: "email", actions: ["read"]))
    }

    @Test("account: with explicit manage action")
    func classifiesAccountManage() {
        #expect(
            ConsentScope.classify("account:repo?action=manage")
                == .account(attr: "repo", actions: ["manage"]))
    }

    @Test("blob: positional single pattern")
    func classifiesBlobPositional() {
        #expect(ConsentScope.classify("blob:image/png") == .blob(accept: ["image/png"]))
    }

    @Test("blob? named multi-value form preserves order")
    func classifiesBlobNamedMultiValue() {
        #expect(
            ConsentScope.classify("blob?accept=image/png&accept=image/jpeg")
                == .blob(accept: ["image/png", "image/jpeg"]))
    }

    @Test("identity:* and identity:handle")
    func classifiesIdentity() {
        #expect(ConsentScope.classify("identity:*") == .identity(attr: "*"))
        #expect(ConsentScope.classify("identity:handle") == .identity(attr: "handle"))
    }

    @Test("include: with percent-encoded aud, per §5.7.1 vectors")
    func classifiesInclude() {
        #expect(ConsentScope.classify("include:com.example.bar") == .include(nsid: "com.example.bar"))
        #expect(
            ConsentScope.classify("include:com.example.baz?aud=did:web:example.com%23my_service")
                == .include(nsid: "com.example.baz"))
    }

    @Test("repo: default actions when omitted")
    func classifiesRepoDefault() {
        #expect(
            ConsentScope.classify("repo:com.example.foo")
                == .repo(collection: ["com.example.foo"], actions: ["create", "update", "delete"]))
    }

    @Test("rpc: positional lxm plus required aud")
    func classifiesRpc() {
        #expect(
            ConsentScope.classify("rpc:com.example.service?aud=did:web:example.com%23service_id")
                == .rpc(aud: "did:web:example.com#service_id", lxm: ["com.example.service"]))
    }

    @Test("space: the bulleted.app scope string from §5.6.1")
    func classifiesSpaceBulletedApp() {
        let scope = ConsentScope.classify(
            "space:app.bulleted.space?manage=create&manage=update&manage=delete&action=read_self")
        guard case let .space(grant) = scope else {
            Issue.record("expected .space, got \(scope)")
            return
        }
        #expect(grant.type == "app.bulleted.space")
        #expect(grant.authority == "self")
        #expect(grant.skey == "*", "skey defaults to '*' — space-permission.ts:189")
        #expect(grant.action_readSelfOnly)
        #expect(Set(grant.manage) == ["create", "update", "delete"])
        #expect(grant.collection.isEmpty)
        #expect(!grant.isUniversal)
    }

    @Test("a specific skey narrows the WHOLE grant to one record, and that must be visible in the label")
    func specificSkeyIsDisclosedInTheSpaceLabel() {
        // Two grants differing ONLY in skey must not render identically —
        // one lets the app touch a single record, the other every record
        // in the space (found in review as a live D19 gap: skey was parsed
        // but never disclosed).
        let scoped = ScopeDescription.render(scopes: ["space:app.bulleted.space?skey=abc123"])
        let unscoped = ScopeDescription.render(scopes: ["space:app.bulleted.space"])
        #expect(scoped.contains("limited to one record"))
        #expect(scoped.contains("<code>abc123</code>"))
        #expect(!unscoped.contains("limited to one record"))
        #expect(scoped != unscoped)

        let scope = ConsentScope.classify("space:app.bulleted.space?skey=abc123")
        guard case let .space(grant) = scope else {
            Issue.record("expected .space, got \(scope)")
            return
        }
        #expect(grant.skey == "abc123")
    }

    @Test("space:*?authority=* is universal")
    func classifiesUniversalSpace() {
        let scope = ConsentScope.classify("space:*?authority=*")
        guard case let .space(grant) = scope else {
            Issue.record("expected .space, got \(scope)")
            return
        }
        #expect(grant.isUniversal)
    }

    @Test("a byte string with no recognised family prefix becomes .unrecognized, never dropped")
    func classifiesUnrecognizedFallback() {
        #expect(ConsentScope.classify("bogus:foo") == .unrecognized(raw: "bogus:foo"))
        #expect(ConsentScope.classify("notafamily:whatever") == .unrecognized(raw: "notafamily:whatever"))
        #expect(ConsentScope.classify("") == .unrecognized(raw: ""))
    }

    @Test("a recognised prefix with a REQUIRED field genuinely absent falls back, not confidently wrong")
    func missingRequiredFieldFallsBackToUnrecognized() {
        // Bare "account" — no attr at all, not even an empty one.
        #expect(ConsentScope.classify("account") == .unrecognized(raw: "account"))
        // rpc: with lxm but no aud — aud has no default (rpc-permission.ts:67-70).
        #expect(ConsentScope.classify("rpc:app.bsky.feed.getFeed") == .unrecognized(raw: "rpc:app.bsky.feed.getFeed"))
        #expect(ConsentScope.classify("space:") == .unrecognized(raw: "space:"))
        #expect(ConsentScope.classify("repo:") == .unrecognized(raw: "repo:"))
    }

    /// `ConsentScope` is a temporary stand-in for Lane 1's `AtprotoScope`,
    /// not a reimplementation of §4/§5's grammar (`classifyFamily`'s doc
    /// comment states exactly what it does and does not check, and why).
    /// So this test does NOT assert full parity with upstream's parser —
    /// that would require this file to duplicate the grammar it is
    /// deliberately avoiding. It asserts the two narrower properties that
    /// are true by design and checkable without a validator:
    ///
    /// 1. For every corpus entry upstream's own parser marks
    ///    `isAtprotoOauthScope: true`, `classify` lands in the matching
    ///    family — never `.unrecognized`. A valid scope silently swallowed
    ///    into the fallback bucket is the failure this guards against.
    /// 2. For every entry — valid OR invalid — the renderer still shows a
    ///    row for it (D19: never drop one, `scope-description.tsx:178`'s
    ///    fallback discipline). This does NOT assert a confident family
    ///    for the invalid entries; several of them (`account:*`,
    ///    `blob:image`, `rpc:*?aud=*`, `space:short`, six `skey=` variants,
    ///    `space:...?unknown=1`) still land in a confident family card
    ///    because their defect is a grammar-shape or enum-membership
    ///    violation this classifier does not check — that gap is real,
    ///    known, and closes when `classify` becomes an `AtprotoScope.parse`
    ///    adapter, not before.
    ///
    /// Re-run after that swap: property 1 becomes the regression proof the
    /// swap preserved behavior, and property 2's "still shows a row" should
    /// continue to hold trivially since the raw list is unconditional.
    @Test("classify() never silently drops a valid corpus scope, and render() never drops any corpus row")
    func classifyAndRenderAgreeWithPinnedGoldenCorpus() throws {
        let fixtureURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // SwanHTTPTests/
            .deletingLastPathComponent()  // Tests/
            .appendingPathComponent("SwanOAuthTests/Fixtures/pinned-typescript-oauth-scopes.json")
        let data = try Data(contentsOf: fixtureURL)
        let root = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let values = try #require(root["values"] as? [[String: Any]])
        #expect(values.count == 52, "corpus shape changed — re-check this test against it")

        let knownPrefixes = ["account", "blob", "identity", "include", "repo", "rpc", "space"]
        var trueEntriesChecked = 0
        var allEntriesChecked = 0
        for entry in values {
            let input = try #require(entry["input"] as? String)
            // Upstream's own verdict — the independent oracle, not derived
            // from this file's own prefix logic.
            let isValid = try #require(entry["isAtprotoOauthScope"] as? Bool)

            // Property 2, for every entry regardless of validity: never
            // silently dropped from the page.
            let rendered = ScopeDescription.render(scopes: [input])
            #expect(
                rendered.contains("<code>\(htmlEscapeForTest(input))</code>"),
                "corpus entry \(input.debugDescription) missing from the advanced raw-scope list")
            allEntriesChecked += 1

            guard isValid else { continue }
            // Property 1, only for entries upstream itself accepts:
            // classify() must land in the matching family, never fall back.
            // `atproto` and the three `transition:*` statics aren't one of
            // the seven families and have their own exact-match cases.
            let classified = ConsentScope.classify(input)
            switch input {
            case "atproto":
                #expect(classified == .atproto)
            case "transition:email":
                #expect(classified == .transitionEmail)
            case "transition:generic":
                #expect(classified == .transitionGeneric)
            case "transition:chat.bsky":
                #expect(classified == .transitionChatBsky)
            default:
                let expectedPrefix = try #require(
                    knownPrefixes.first { input == $0 || input.hasPrefix($0 + ":") || input.hasPrefix($0 + "?") },
                    "valid corpus entry \(input.debugDescription) matches no known family prefix")
                switch (expectedPrefix, classified) {
                case ("account", .account), ("blob", .blob), ("identity", .identity), ("include", .include),
                    ("repo", .repo), ("rpc", .rpc), ("space", .space):
                    break
                default:
                    Issue.record(
                        "valid corpus entry \(input.debugDescription) expected family \(expectedPrefix), classify() returned \(classified)"
                    )
                }
            }
            trueEntriesChecked += 1
        }
        #expect(allEntriesChecked == 52)
        #expect(trueEntriesChecked == 36, "expected 36 isAtprotoOauthScope:true entries in the pinned corpus")
    }

    private func htmlEscapeForTest(_ value: String) -> String {
        value.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }

    // MARK: - ScopeDescription.render — S4.1a

    @Test("bare atproto alone renders no permission card, but stays in the advanced raw list")
    func atprotoAloneRendersNoCard() {
        let html = ScopeDescription.render(scopes: ["atproto"])
        #expect(!html.contains("Requested access:"))
        #expect(html.contains("<code>atproto</code>"))
    }

    @Test("atproto alongside a real scope still gets no card of its own")
    func atprotoNeverGetsACardEvenWithOtherScopes() {
        let html = ScopeDescription.render(scopes: ["atproto", "identity:handle"])
        #expect(html.contains("Requested access:"))
        // "Identity" card exists; nothing titles a card "Atproto".
        #expect(html.contains("Identity"))
        #expect(!html.contains("<h3>atproto</h3>"))
    }

    // MARK: - S4.1b / S4.1c / S4.1d — space

    @Test("a space: grant renders the Spaces card with verbs in prose")
    func spaceGrantRendersCard() {
        let html = ScopeDescription.render(
            scopes: ["space:app.bulleted.space?manage=update&action=read_self"])
        #expect(html.contains("Spaces"))
        #expect(html.contains("app.bulleted.space"))
        #expect(html.contains("read only your own data"))
        #expect(html.contains("Update the space"))
    }

    @Test("type=='*' && authority=='*' triggers the universal-space warning; a scoped grant does not")
    func universalSpaceWarningIsConditional() {
        let universal = ScopeDescription.render(scopes: ["space:*?authority=*"])
        #expect(universal.contains("every space"))
        #expect(universal.contains("deeply trust"))

        let scoped = ScopeDescription.render(scopes: ["space:app.bulleted.space"])
        #expect(!scoped.contains("every space"))
    }

    @Test("a space type this renderer has no name for still shows a row via the raw NSID")
    func unnamedSpaceTypeFallsBackToRawNSID() {
        let html = ScopeDescription.render(scopes: ["space:com.example.totallyUnknownType"])
        #expect(html.contains("com.example.totallyUnknownType"))
    }

    // MARK: - S4.2 — the one canonical include: string, verbatim

    @Test("include: renders the exact canonical Phase-1 wording (§5.7.2, §9-D19)")
    func includeRendersCanonicalWording() {
        let html = ScopeDescription.render(scopes: ["include:com.example.bar"])
        let text = stripTags(html)
        let expected =
            "Requested permission set com.example.bar. Swan does not currently grant capabilities derived from this set."
        #expect(text.contains(expected))
    }

    // MARK: - D11 / §9-D19 — transition:* recognised, grants nothing, never raw-only

    @Test("transition: scopes render a semantic card, not bare bytes")
    func transitionScopesRenderSemanticCard() {
        for raw in ["transition:email", "transition:generic", "transition:chat.bsky"] {
            let html = ScopeDescription.render(scopes: [raw])
            #expect(html.contains("Legacy compatibility"), "missing card for \(raw)")
            #expect(html.contains("grant any capability"), "missing 'grants nothing' wording for \(raw)")
        }
    }

    // MARK: - S4.3 — identity:* theft warning

    @Test("identity:* carries the full-control/permanently-break/steal warning")
    func identityWildcardCarriesTheftWarning() {
        let html = ScopeDescription.render(scopes: ["identity:*"])
        #expect(html.contains("permanently break"))
        #expect(html.contains("steal"))
    }

    @Test("identity:handle alone does not carry the theft warning")
    func identityHandleAloneHasNoTheftWarning() {
        let html = ScopeDescription.render(scopes: ["identity:handle"])
        #expect(!html.contains("permanently break"))
        #expect(!html.contains("steal"))
    }

    // MARK: - D19: account/blob/repo/rpc get cards whether or not Swan routes consume them

    @Test("account/blob/repo/rpc each render a card even though no Swan route consumes them yet")
    func unroutedFamiliesStillGetCards() {
        let html = ScopeDescription.render(
            scopes: [
                "account:email", "blob:image/*", "repo:com.example.foo",
                "rpc:com.example.method?aud=*",
            ])
        #expect(html.contains("Account"))
        #expect(html.contains("File uploads"))
        #expect(html.contains("Repository"))
        #expect(html.contains("External service calls"))
    }

    // MARK: - S4.4 — raw scope text survives as advanced detail

    @Test("raw scope bytes remain available below the semantic cards")
    func rawScopesSurviveAsAdvancedDetail() {
        let html = ScopeDescription.render(scopes: ["space:app.bulleted.space", "identity:handle"])
        #expect(html.contains("<details>"))
        #expect(html.contains("<code>space:app.bulleted.space</code>"))
        #expect(html.contains("<code>identity:handle</code>"))
    }

    // MARK: - S4.5 — one renderer, deterministic output

    @Test("render is deterministic for the same scope set (both consent pages share one function)")
    func renderIsDeterministic() {
        let scopes: Set<String> = ["atproto", "space:app.bulleted.space?action=read_self", "identity:*"]
        #expect(ScopeDescription.render(scopes: scopes) == ScopeDescription.render(scopes: scopes))
    }

    // MARK: - helpers

    private func stripTags(_ html: String) -> String {
        var result = ""
        var insideTag = false
        for char in html {
            if char == "<" { insideTag = true; continue }
            if char == ">" { insideTag = false; continue }
            if !insideTag { result.append(char) }
        }
        return result
    }
}

extension ConsentScope.SpaceGrant {
    /// Test-only convenience: true when this grant's `action` set is exactly
    /// what §5.6.1's bulleted.app vector expects (`read_self` only).
    fileprivate var action_readSelfOnly: Bool {
        actions == ["read_self"]
    }
}
