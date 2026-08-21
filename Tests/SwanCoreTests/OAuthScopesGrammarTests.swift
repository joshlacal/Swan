import Foundation
import Testing
@testable import SwanCore

/// Grammar-layer conformance: `ScopeStringSyntax`, `ScopeParameterBag`,
/// `AtprotoSyntax`. Vectors copied inline from
/// docs/superpowers/specs/2026-08-14-oauth-permission-scopes-design.md §4,
/// which are themselves cross-checked against
/// `Tests/SwanOAuthTests/Fixtures/pinned-typescript-oauth-scopes.json`
/// (this suite may not read that fixture directly — see the lane brief).
@Suite("OAuthScopes grammar layer")
struct OAuthScopesGrammarTests {
    // MARK: ScopeToken (§4.2)

    @Test
    func scopeTokenExcludesQuoteAndBackslash() {
        #expect(ScopeToken.isScopeToken("account:email"))
        #expect(!ScopeToken.isScopeToken("has space"))
        #expect(!ScopeToken.isScopeToken("has\"quote"))
        #expect(!ScopeToken.isScopeToken("has\\backslash"))
        #expect(!ScopeToken.isScopeToken(""))
    }

    // MARK: ScopeStringSyntax lexing (§4.4, syntax-string.test.ts)

    @Test
    func emptyPositionalIsLegalAndDistinctFromAbsent() throws {
        let withColon = try ScopeStringSyntax.parse("my-res:")
        #expect(withColon.positional == "")
        let bare = try ScopeStringSyntax.parse("my-res")
        #expect(bare.positional == nil)
    }

    @Test
    func literalQuestionMarkInsidePositionalBelongsToPositional() throws {
        // syntax-string.test.ts:36-42 — the FIRST `?` starts the query; a
        // literal `?` in a value belongs to the preceding value only if it is
        // percent-encoded. This checks the split point itself: `rpc:a?b=1`
        // splits positional="a", query="b=1".
        let syntax = try ScopeStringSyntax.parse("rpc:a?b=1")
        #expect(syntax.positional == "a")
        #expect(syntax.parameters.values(for: "b") == ["1"])
    }

    @Test
    func laterHashIsALiteralNotAFragment() throws {
        // include-scope.test.ts:32-39 — this is a query string, not a URL.
        let a = try ScopeStringSyntax.parse("include:com.example.baz?aud=did:web:example.com%23my_service")
        let b = try ScopeStringSyntax.parse("include:com.example.baz?aud=did:web:example.com#my_service")
        #expect(a.parameters.values(for: "aud") == ["did:web:example.com#my_service"])
        #expect(b.parameters.values(for: "aud") == ["did:web:example.com#my_service"])
    }

    @Test
    func isScopeStringRejectsSuperstringFalsePositives() {
        // syntax.test.ts:32-42
        #expect(!ScopeStringSyntax.isScopeString("prefixes", for: "prefix"))
        #expect(ScopeStringSyntax.isScopeString("prefix", for: "prefix"))
        #expect(ScopeStringSyntax.isScopeString("prefix:x", for: "prefix"))
        #expect(ScopeStringSyntax.isScopeString("prefix?x=1", for: "prefix"))
    }

    // MARK: percent-decoding asymmetry (§4.4)

    @Test
    func positionalPercentDecodingThrowsOnMalformedEscape() {
        #expect(throws: ScopeParseError.self) {
            try ScopeStringSyntax.parse("account:100%")
        }
    }

    @Test
    func queryPercentDecodingIsLossyAndNeverThrows() throws {
        // `%` is in the DID charset (syntax/src/did.ts:51); a malformed escape
        // in a QUERY value must survive as literal bytes, not throw — this is
        // what keeps `space:*?authority=did:web:ex%ample.com` parseable (§4.4).
        let syntax = try ScopeStringSyntax.parse("space:*?authority=did:web:ex%ample.com")
        #expect(syntax.parameters.values(for: "authority") == ["did:web:ex%ample.com"])
    }

    @Test
    func emptyQueryPairIsSkippedNotRejected() throws {
        // rpc-permission.ts canonicalisation row: `rpc:com.example.method1?&aud=*`
        // -> `rpc:com.example.method1?aud=*` (empty pair skipped, matching
        // URLSearchParams). This is fence vector D10 (§7.3) — Swan today
        // (SwanCore.swift:218-227) rejects an empty pair; the new grammar must not.
        let syntax = try ScopeStringSyntax.parse("rpc:com.example.method1?&aud=*")
        #expect(syntax.parameters.values(for: "aud") == ["*"])
    }

    @Test
    func plusFoldsToSpaceOnlyInQueryValues() throws {
        let syntax = try ScopeStringSyntax.parse("space:x?skey=a+b")
        #expect(syntax.parameters.values(for: "skey") == ["a b"])
    }

    // MARK: canonical serialiser (§4.5)

    @Test
    func canonicalSerialiserUsesFormEncodingForQueryAndUriComponentForPositional() throws {
        let syntax = ScopeStringSyntax(
            prefix: "rpc",
            positional: "com.example.service",
            parameters: ScopeParameterBag([.init(key: "aud", value: "did:web:example.com#service_id")])
        )
        // "#" is not in ALLOWED_SCOPE_CHARS -> %23, per rpc-permission.test.ts:33-37.
        #expect(try syntax.canonicalString() == "rpc:com.example.service?aud=did:web:example.com%23service_id")
    }

    @Test
    func tildeSurvivesRawInPositionalButIsEscapedInQuery() throws {
        // Generated golden asymmetry, §4.5 — pinned so a future reader does not
        // "fix" the encoder and diverge from the reference.
        let positionalTilde = ScopeStringSyntax(prefix: "space", positional: "a~b")
        #expect(try positionalTilde.canonicalString() == "space:a~b")

        let queryTilde = ScopeStringSyntax(
            prefix: "space",
            positional: "x",
            parameters: ScopeParameterBag([.init(key: "skey", value: "a~b")])
        )
        #expect(try queryTilde.canonicalString() == "space:x?skey=a%7Eb")
    }

    // MARK: AtprotoSyntax — DID / NSID / record-key (§4.1)

    @Test
    func nsidDivergencesFromSwansCurrentValidatorResolveInUpstreamsFavour() {
        // §9-D3, all three divergences.
        #expect(!AtprotoSyntax.isValidNSID("com.example.foo-bar")) // upstream REJECT
        #expect(!AtprotoSyntax.isValidNSID("com.example-.foo")) // upstream REJECT
        #expect(AtprotoSyntax.isValidNSID("com.9example.foo")) // upstream ACCEPT (false negative fixed)
    }

    @Test
    func nsidRequiresAtLeastThreeSegmentsAndRejectsLeadingDigitOnlyOnFirstSegment() {
        #expect(!AtprotoSyntax.isValidNSID("short.a")) // < 3 labels
        #expect(!AtprotoSyntax.isValidNSID("9com.example.foo")) // segment 0 leading digit -> reject
        #expect(AtprotoSyntax.isValidNSID("com.example.foo"))
    }

    @Test
    func didGrammarRejectsTrailingColonAndBareDidPrefix() {
        #expect(!AtprotoSyntax.isValidDID("did:")) // space:*?authority=did: must be nil
        #expect(!AtprotoSyntax.isValidDID("not-a-did"))
        #expect(AtprotoSyntax.isValidDID("did:plc:abc123xyz"))
    }

    @Test
    func recordKeyAcceptsExactlyUpstreamsPositiveAndNegativeVectors() {
        // space-permission.test.ts:114-126 (accept) / :128-143 (reject)
        for accepted in ["self", "3jui7kd54zh2y", "a.b-c_d~e:f", String(repeating: "x", count: 512)] {
            #expect(AtprotoSyntax.isValidRecordKey(accepted))
        }
        for rejected in ["hello world", ".", "..", "a/b", "a#b", String(repeating: "x", count: 513)] {
            #expect(!AtprotoSyntax.isValidRecordKey(rejected))
        }
    }

    // MARK: AtprotoSyntax — did-ref / atproto did-ref (§4.1, §9-D13)

    @Test
    func didRefAbsoluteUpstreamVectors() {
        // packages/did/tests/did-ref.test.ts:4-41
        #expect(AtprotoSyntax.isValidAtprotoDIDRefAbsolute("did:plc:l3rouwludahu3ui3bt66mfvj#atproto"))
        #expect(AtprotoSyntax.isValidAtprotoDIDRefAbsolute("did:web:example.com#service_id"))
        #expect(AtprotoSyntax.isValidAtprotoDIDRefAbsolute("did:web:example.com#atproto_label"))
        #expect(!AtprotoSyntax.isValidAtprotoDIDRefAbsolute("did:plc:l3rouwludahu3ui3bt66mfvj"))
        #expect(!AtprotoSyntax.isValidAtprotoDIDRefAbsolute("did:web:example.com"))
        #expect(!AtprotoSyntax.isValidAtprotoDIDRefAbsolute("#atproto"))
        #expect(!AtprotoSyntax.isValidAtprotoDIDRefAbsolute(""))
        #expect(!AtprotoSyntax.isValidAtprotoDIDRefAbsolute("did:plc:l3rouwludahu3ui3bt66mfvj#"))
        #expect(!AtprotoSyntax.isValidAtprotoDIDRefAbsolute("did:plc:l3rouwludahu3ui3bt66mfvj##foo"))
        #expect(!AtprotoSyntax.isValidAtprotoDIDRefAbsolute("did:plc:l3rouwludahu3ui3bt66mfvj#a#b"))
        #expect(!AtprotoSyntax.isValidAtprotoDIDRefAbsolute("did:foo:bar#baz")) // method not plc/web
        // But the GENERIC did-ref accepts it (§9-D13's split) — the whole point
        // of keeping the two validators separate.
        #expect(AtprotoSyntax.isValidDIDRefAbsolute("did:foo:bar#baz"))
    }

    @Test
    func atprotoDidWebExcludesPathsAndNonLocalhostPorts() {
        // Three vectors upstream proves elsewhere (§4.1) — the ones a
        // reconstruction from the generic DID grammar alone gets wrong.
        #expect(!AtprotoSyntax.isValidAtprotoDIDRefAbsolute("did:web:example.com:admin#atproto"))
        #expect(AtprotoSyntax.isValidAtprotoDIDRefAbsolute("did:web:localhost%3A8080#atproto"))
        #expect(!AtprotoSyntax.isValidAtprotoDIDRefAbsolute("did:web:example.com%3A8443#atproto"))
    }

    @Test
    func atprotoDidPlcIsFixedLengthBase32() {
        #expect(!AtprotoSyntax.isValidAtprotoDIDRefAbsolute("did:plc:111#service_id")) // wrong length + charset
    }

    // MARK: §4.6 schema-level rejections, exact case pinned (not just "throws")

    /// Previously only exercised indirectly (an rpc positional+named vector
    /// asserted generic `throws: ScopeParseError.self`, never the specific
    /// case) and never exercised at all for the repeated-single-valued class.
    /// Both classes are also absent from the pinned golden corpus's 16
    /// invalid entries, so a consent-renderer audit of a hand-rolled bridge
    /// parser (`Sources/SwanHTTP/ScopeDescription.swift` in L4's lane) could
    /// not have been caught by a corpus-driven test either — pin the exact
    /// case here so the class itself has a positive control independent of
    /// the corpus.
    @Test
    func positionalAndNamedConflictIsPinnedAcrossFamilies() {
        // parser.ts:124-127 — positional and named form of the SAME key
        // present together is a hard reject, regardless of family or of
        // whether the two values agree.
        #expect(throws: ScopeParseError.positionalAndNamedConflict(prefix: "account", key: "attr")) {
            try AccountPermission.parse("account:email?attr=repo")
        }
        #expect(throws: ScopeParseError.positionalAndNamedConflict(prefix: "identity", key: "attr")) {
            try IdentityPermission.parse("identity:handle?attr=*")
        }
        #expect(throws: ScopeParseError.positionalAndNamedConflict(prefix: "space", key: "type")) {
            try SpacePermission.parse("space:com.example.type?type=com.other.type")
        }
        #expect(throws: ScopeParseError.positionalAndNamedConflict(prefix: "rpc", key: "lxm")) {
            // rpc-permission.test.ts:65-71 — upstream's own vector.
            try RpcPermission.parse("rpc:com.example.method1?aud=did:web:example.com&lxm=com.example.method2")
        }
    }

    @Test
    func repeatedSingleValuedParameterIsPinnedAcrossFamilies() {
        // syntax-string.ts:18-23 -> parser.ts:121-122 — a single-valued
        // parameter named more than once is `null`, not "use the last (or
        // first) value silently". `repo` has no non-positional single-valued
        // parameter (`collection` and `action` are both `.multiple`), so it
        // cannot produce this case at all — every other family can.
        #expect(throws: ScopeParseError.repeatedSingleValuedParameter(prefix: "account", key: "attr")) {
            try AccountPermission.parse("account?attr=email&attr=repo")
        }
        #expect(throws: ScopeParseError.repeatedSingleValuedParameter(prefix: "identity", key: "attr")) {
            try IdentityPermission.parse("identity?attr=handle&attr=*")
        }
        #expect(throws: ScopeParseError.repeatedSingleValuedParameter(prefix: "include", key: "nsid")) {
            try IncludeScope.parse("include?nsid=com.example.foo&nsid=com.example.bar")
        }
        #expect(throws: ScopeParseError.repeatedSingleValuedParameter(prefix: "include", key: "aud")) {
            try IncludeScope.parse(
                "include:com.example.foo?aud=did:web:example.com%23a&aud=did:web:example.com%23b"
            )
        }
        #expect(throws: ScopeParseError.repeatedSingleValuedParameter(prefix: "rpc", key: "aud")) {
            try RpcPermission.parse(
                "rpc:com.example.method?aud=did:web:example.com%23a&aud=did:web:example.com%23b"
            )
        }
        #expect(throws: ScopeParseError.repeatedSingleValuedParameter(prefix: "space", key: "authority")) {
            try SpacePermission.parse("space:com.example.type?authority=did:plc:aaa&authority=did:plc:bbb")
        }
        #expect(throws: ScopeParseError.repeatedSingleValuedParameter(prefix: "space", key: "skey")) {
            try SpacePermission.parse("space:com.example.type?skey=abc&skey=def")
        }
    }

    /// The mirror finding from the same audit: `ConsentScope`'s bridge parser
    /// never percent-decodes a POSITIONAL segment at all (only query values),
    /// so a percent-escaped positional would render its raw undecoded bytes.
    /// The real grammar decodes it via `decodeURIComponent` (§4.4) before
    /// validation. No corpus entry exercises this (checked with a script), so
    /// pin it here as a positive control on the correct behaviour.
    @Test
    func percentEscapedPositionalDecodesBeforeValidation() throws {
        let decoded = try RepoPermission.parse("repo:com%2Eexample%2Efoo")
        #expect(decoded.collection == [.nsid("com.example.foo")])
        #expect(try decoded.canonicalScopeString() == "repo:com.example.foo")
    }
}
