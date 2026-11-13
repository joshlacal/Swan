import Foundation
import SwanCore
import Testing

@testable import SwanHTTP

/// Consent display classification must stay a thin, fail-closed adapter over
/// the admission grammar in `AtprotoScope.parse`. The renderer still consumes
/// `ConsentScope` so its presentation defaults remain local to SwanHTTP.
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

    @Test("a specific skey selects a space, not a single record")
    func specificSkeyIsDisclosedInTheSpaceLabel() {
        // Two grants differing ONLY in skey must not render identically —
        // one selects a particular space key, the other every matching space.
        let scoped = ScopeDescription.render(scopes: ["space:app.bulleted.space?skey=abc123"])
        let unscoped = ScopeDescription.render(scopes: ["space:app.bulleted.space"])
        #expect(scoped.contains("limited to space key"))
        #expect(!scoped.contains("limited to one record"))
        #expect(scoped.contains("<code>abc123</code>"))
        #expect(!unscoped.contains("limited to space key"))
        #expect(scoped != unscoped)

        let scope = ConsentScope.classify("space:app.bulleted.space?skey=abc123")
        guard case let .space(grant) = scope else {
            Issue.record("expected .space, got \(scope)")
            return
        }
        #expect(grant.skey == "abc123")
    }

    @Test("space declarations show title and fall back to NSID")
    func spaceDeclarationTitleAndFallback() {
        let scope = "space:app.bulleted.space"
        let titled = ScopeDescription.render(
            scopes: [scope],
            spaceTitles: ["app.bulleted.space": "Bulleted Forum"]
        )
        #expect(titled.contains("<code>Bulleted Forum</code> spaces"))

        let untitled = ScopeDescription.render(scopes: [scope])
        #expect(untitled.contains("<code>app.bulleted.space</code> spaces"))
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

    /// The pinned 62-row corpus is exercised against Swan's admission parser,
    /// not its upstream boolean field, so display and admission cannot drift:
    /// every successful parse must map to the same semantic family, every
    /// parser failure must retain the exact raw scope as `.unrecognized`, and
    /// every original input must remain escaped in Advanced details.
    @Test("all pinned corpus rows mirror admission parsing and keep escaped raw details")
    func classifyAndRenderAgreeWithPinnedGoldenCorpus() throws {
        let fixtureURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // SwanHTTPTests/
            .deletingLastPathComponent()  // Tests/
            .appendingPathComponent("SwanOAuthTests/Fixtures/pinned-typescript-oauth-scopes.json")
        let data = try Data(contentsOf: fixtureURL)
        let root = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let values = try #require(root["values"] as? [[String: Any]])
        #expect(values.count == 62, "corpus shape changed — re-check this test against it")

        var parsedEntriesChecked = 0
        var rejectedEntriesChecked = 0
        var allEntriesChecked = 0
        for entry in values {
            let input = try #require(entry["input"] as? String)

            // Every input, accepted or rejected, remains escaped in the
            // dedicated Advanced-details list below the semantic cards.
            let rendered = ScopeDescription.render(scopes: [input])
            #expect(
                rendered.contains(
                    "<code class=\"font-mono\">\(htmlEscapeForTest(input))</code>"),
                "corpus entry \(input.debugDescription) missing from the advanced raw-scope list")
            allEntriesChecked += 1

            let classified = ConsentScope.classify(input)
            do {
                let parsed = try AtprotoScope.parse(input)
                switch (parsed, classified) {
                case (.atproto, .atproto),
                     (.transitionEmail, .transitionEmail),
                     (.transitionGeneric, .transitionGeneric),
                     (.transitionChatBsky, .transitionChatBsky),
                     (.account, .account),
                     (.blob, .blob),
                     (.identity, .identity),
                     (.include, .include),
                     (.repo, .repo),
                     (.rpc, .rpc),
                     (.space, .space):
                    break
                default:
                    Issue.record(
                        "parsed corpus entry \(input.debugDescription) expected family \(parsed), classify() returned \(classified)"
                    )
                }
                parsedEntriesChecked += 1
            } catch {
                #expect(
                    classified == .unrecognized(raw: input),
                    "parser-rejected corpus entry \(input.debugDescription) classified confidently as \(classified)"
                )
                rejectedEntriesChecked += 1
            }
        }
        #expect(allEntriesChecked == 62)
        #expect(parsedEntriesChecked == 37, "expected 37 parser-accepted entries in the pinned corpus")
        #expect(rejectedEntriesChecked == 25, "expected 25 parser-rejected entries in the pinned corpus")
    }

    @Test("positional conflicts and repeated single-valued parameters fall back to their raw scopes")
    func parserRejectedStructuralControlsFallBackToRaw() {
        let conflict = "account:email?attr=repo"
        #expect(throws: ScopeParseError.positionalAndNamedConflict(prefix: "account", key: "attr")) {
            try AtprotoScope.parse(conflict)
        }

        let repeated = "space:com.example.type?authority=did:plc:aaa&authority=did:plc:bbb"
        #expect(throws: ScopeParseError.repeatedSingleValuedParameter(prefix: "space", key: "authority")) {
            try AtprotoScope.parse(repeated)
        }

        for raw in [conflict, repeated] {
            #expect(ConsentScope.classify(raw) == .unrecognized(raw: raw))
            #expect(
                ScopeDescription.render(scopes: [raw]).contains(
                    "<code class=\"font-mono\">\(htmlEscapeForTest(raw))</code>"),
                "parser-rejected control \(raw.debugDescription) missing from Advanced details"
            )
        }
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
        #expect(html.contains(">atproto</code>"))
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

    @Test("collection-qualified reads describe all collections while writes retain their collection constraint")
    func spaceReadsAndWritesHaveSeparateCollectionDescriptions() {
        for (action, expectedRead) in [
            ("read", "read all data in the space"),
            ("read_self", "read only your own data across all collections in the space"),
        ] {
            let html = ScopeDescription.render(scopes: [
                "space:app.example.space?action=\(action)&action=create&collection=app.example.record",
            ])
            #expect(html.contains(expectedRead))
            #expect(html.contains("create records in <code>app.example.record</code>"))
            #expect(!html.contains("declared collections"))
        }
    }

    @Test("omitted collections disclose changing declaration defaults for concrete space types only")
    func defaultSpaceWriteCollectionsAreDisclosed() {
        let concrete = ScopeDescription.render(scopes: ["space:app.example.space"])
        #expect(concrete.contains("create, update, and delete records in this space type's declared collections, which may change"))
        let wildcard = ScopeDescription.render(scopes: ["space:*"])
        #expect(!wildcard.contains("declared collections"))
        #expect(!wildcard.contains("create, update, and delete records"))
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

    @Test("an unexpanded include: renders the canonical grants-nothing wording (§5.7.2, §9-D19)")
    func includeRendersCanonicalWording() {
        let html = ScopeDescription.render(scopes: ["include:com.example.bar"])
        let text = stripTags(html)
        let expected =
            "Requested permission set com.example.bar. Swan does not currently grant capabilities derived from this set."
        #expect(text.contains(expected))
    }

    /// §5.7.5's last row: an `include:` that Phase-2 resolution proved and
    /// expanded to **zero** grants is not an error, and must still be rendered.
    ///
    /// By that point the `include:` string is gone — expansion replaced it, and
    /// an empty expansion replaced it with nothing — so the NSID arrives on its
    /// own channel. If it did not reach the page, the only trace would be a
    /// `.warn` in the operator's log, which the person authorizing never sees;
    /// the permission set would simply have vanished from the consent screen.
    @Test("an empty Phase-2 expansion renders the same canonical string, naming the NSID")
    func emptyExpansionRendersCanonicalWording() {
        let html = ScopeDescription.render(
            scopes: ["atproto"], emptyPermissionSets: ["com.example.bar"]
        )
        let text = stripTags(html)
        #expect(
            text.contains(
                "Requested permission set com.example.bar. Swan does not currently grant capabilities derived from this set."
            )
        )
    }

    /// One NSID, two routes to the same card — an unexpanded pass-through
    /// `include:` still in the scope set and an empty expansion naming it —
    /// must print once.
    @Test("an NSID reaching the include card both ways is not printed twice")
    func includeNSIDIsNotDuplicatedAcrossBothChannels() {
        let html = ScopeDescription.render(
            scopes: ["include:com.example.bar"], emptyPermissionSets: ["com.example.bar"]
        )
        let text = stripTags(html)
        let needle = "Requested permission set com.example.bar."
        var count = 0
        var cursor = text.startIndex
        while let found = text.range(of: needle, range: cursor ..< text.endIndex) {
            count += 1
            cursor = found.upperBound
        }
        #expect(count == 1)
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
        #expect(html.contains("<details"))
        #expect(html.contains(">space:app.bulleted.space</code>"))
        #expect(html.contains(">identity:handle</code>"))
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
