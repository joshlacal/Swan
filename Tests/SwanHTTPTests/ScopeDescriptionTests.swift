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
        #expect(grant.action_readSelfOnly)
        #expect(Set(grant.manage) == ["create", "update", "delete"])
        #expect(grant.collection.isEmpty)
        #expect(!grant.isUniversal)
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

    @Test("a byte string this bridge parser cannot place becomes .unrecognized, never dropped")
    func classifiesUnrecognizedFallback() {
        #expect(ConsentScope.classify("bogus:foo") == .unrecognized(raw: "bogus:foo"))
        // Malformed but prefix-matching input also falls back rather than crashing.
        #expect(ConsentScope.classify("account") == .unrecognized(raw: "account"))
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
        #expect(html.contains("update the space"))
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
        #expect(
            text.contains(
                "Requested permission set com.example.bar. "
                    + "Swan does not currently grant capabilities derived from this set."))
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
