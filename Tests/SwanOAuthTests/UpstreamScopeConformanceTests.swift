import Foundation
import XCTest
@testable import SwanCore

/// Drives Swift against every section of the golden corpus (§7.1a, §7.2).
///
/// No expectation in this file is hand-written: each one is decoded from
/// `Fixtures/pinned-typescript-oauth-scopes.json`, which was produced by running
/// upstream's own `@atproto/oauth-scopes` at `bddc99fb`. Where the spec's prose
/// and the fixture disagree, the fixture wins and the disagreement is reported.
///
/// Rows where Swan deliberately diverges from upstream are asserted **as
/// divergences**, in their own tests, with the deciding section named. A
/// divergence silently folded into a conformance loop is how a future reader
/// "fixes" Swan toward upstream and reopens a ruled question.
final class UpstreamScopeConformanceTests: XCTestCase, @unchecked Sendable {
    // MARK: - `values`: per-value parse + canonical form

    /// 52 rows. For each: does Swan's parser agree with upstream about whether
    /// the string is a scope at all, and — when it is — does Swan produce the
    /// same canonical bytes?
    func testEveryCorpusValueParsesAndCanonicalisesAsUpstreamDoes() throws {
        let corpus = try UpstreamScopeCorpus.load()
        for value in corpus.values {
            let parsed: AtprotoScope?
            do {
                parsed = try AtprotoScope.parse(value.input)
            } catch {
                parsed = nil
                if value.parses {
                    XCTFail(
                        "corpus says \(value.input.debugDescription) parses to "
                            + "\(value.canonical!.debugDescription); Swan threw \(error)"
                    )
                }
            }
            guard let expected = value.canonical else {
                XCTAssertNil(
                    parsed,
                    "corpus says \(value.input.debugDescription) does NOT parse; Swan accepted it"
                )
                continue
            }
            guard let parsed else { continue }
            let canonical = try parsed.canonicalScopeString()
            XCTAssertEqual(
                canonical,
                expected,
                "canonical form diverges for \(value.input.debugDescription)"
            )
        }
    }

    /// Canonicalisation must be idempotent wherever upstream says it is: the
    /// canonical form re-parses to itself. This is the property §9-D7's
    /// registered-vs-requested subset check rests on.
    func testCanonicalFormsAreStableWhereUpstreamSaysTheyAre() throws {
        let corpus = try UpstreamScopeCorpus.load()
        for value in corpus.values where value.roundTripStable == true {
            let canonical = try XCTUnwrap(value.canonical)
            let reparsed = try AtprotoScope.parse(canonical)
            XCTAssertEqual(
                try reparsed.canonicalScopeString(),
                canonical,
                "canonical form of \(value.input.debugDescription) is not stable in Swan"
            )
        }
    }

    /// The `%` positional/query asymmetry (§4.4, S12b/S12c) reaches the corpus as
    /// ordinary rows; assert the ones that matter by name so a symmetric-strict
    /// decoder cannot pass the loop above by rejecting both halves.
    func testMalformedPercentInAQueryValueDoesNotThrow() throws {
        let corpus = try UpstreamScopeCorpus.load()
        // `%25` in a skey: upstream REJECTS it — at the family validator, not at
        // the decoder. The distinction is the point: a decoder throw here would
        // be a hard `invalid_scope` on the whole PAR (§9-D5).
        let row = try XCTUnwrap(corpus.values.first { $0.input == "space:com.example.group?skey=a%25b" })
        XCTAssertFalse(row.parses, "corpus expectation changed; re-derive this test from it")
        do {
            _ = try AtprotoScope.parse(row.input)
            XCTFail("expected a validator rejection")
        } catch let error as ScopeParseError {
            XCTAssertNotEqual(
                error,
                .malformedPercentEncoding(row.input),
                """
                A malformed/awkward `%` in a QUERY value must not throw at the \
                decoder (§4.4): `URLSearchParams` leaves it as literal bytes, and \
                the rejection must come from the family's `validate`. Throwing at \
                the decoder rejects scopes upstream accepts — \
                `space:*?authority=did:web:ex%ample.com` is the interop failure \
                this change exists to remove (S12c).
                """
            )
        }
    }

    // MARK: - `strings`: whole scope-string normalisation

    /// Swan's whole-string canonicalisation is upstream's
    /// `normalizeAtprotoOauthScope` **minus its drop step** (§9-D7): per-value
    /// canonicalisation and `.sort()` are adopted; "silently remove values that
    /// do not parse" is rejected for the registered side and impossible for the
    /// requested side, which is rejected outright at PAR (§9-D5).
    ///
    /// So this loop drives only the rows where every token parses. The rows where
    /// one does not are asserted as divergences below.
    func testWholeScopeStringNormalisationMatchesUpstreamWhereEveryTokenParses() throws {
        let corpus = try UpstreamScopeCorpus.load()
        for row in corpus.strings {
            let tokens = row.input.split(separator: " ").map(String.init)
            let canonicalised = try? tokens.map { token -> String in
                try AtprotoScope.parse(token).canonicalScopeString()
            }
            guard let canonicalised else { continue }  // divergence rows, below
            XCTAssertEqual(
                canonicalised.sorted().joined(separator: " "),
                row.normalized,
                "whole-string normalisation diverges for \(row.input.debugDescription)"
            )
        }
    }

    /// **DIVERGENCE, ruled at §9-D5 and §9-D7.** Upstream's whole-string
    /// normaliser drops a token that does not parse:
    /// `atproto notafamily:whatever` → `atproto`. Swan does not have that
    /// behaviour anywhere, in either direction:
    ///
    ///  * requested side — rejected at PAR with `invalid_scope`, because a
    ///    silent narrowing hands the client an `atproto`-only token and then an
    ///    opaque 401 at the resource plane with nothing pointing at the cause;
    ///  * registered side — **kept, compared as raw bytes**, because dropping it
    ///    turns a subset check that passes today into a lockout over a scope the
    ///    client is not even asking for.
    ///
    /// Named `…UnlikeUpstream` so nobody "fixes" it toward the fixture.
    func testUnparseableTokenIsNeverSilentlyDroppedUnlikeUpstream() throws {
        let corpus = try UpstreamScopeCorpus.load()
        let row = try XCTUnwrap(corpus.strings.first { $0.input.contains("notafamily:whatever") })
        XCTAssertEqual(row.normalized, "atproto", "corpus changed; re-derive this divergence")

        // Swan's parser rejects the token — loudly, with a typed error naming the
        // family that could not be found, rather than returning nil.
        do {
            _ = try AtprotoScope.parse("notafamily:whatever")
            XCTFail("`notafamily:whatever` must not parse")
        } catch let error as ScopeParseError {
            XCTAssertEqual(error, .unknownPrefix("notafamily:whatever"))
        }

        // And a permissions value HOLDING it neither throws nor fails open: it
        // grants nothing and is retained for logging (§9-D5 match layer).
        let permissions = SwanScopePermissions(
            rawScopes: ["atproto", "notafamily:whatever"],
            subject: nil
        )
        XCTAssertEqual(Set(permissions.rejected.keys), ["notafamily:whatever"])
        XCTAssertEqual(
            permissions.rawScopes,
            ["atproto", "notafamily:whatever"],
            "the raw strings must survive verbatim — persistence and audit never see a re-serialised value"
        )
        XCTAssertTrue(permissions.hasBaseATProtocolScope)
        XCTAssertFalse(permissions.hasResourceScope, "atproto alone is the floor, not a resource grant")
    }

    /// **DIVERGENCE, structural.** Upstream's normaliser does not deduplicate:
    /// `atproto atproto` → `atproto atproto` (split/map/filter/sort/join, no
    /// `Set`). Swan cannot reproduce that at any layer it persists through —
    /// `OAuthTokenBinding.scopes` is a `Set<String>` and
    /// `OAuthControlStore.encodeScopes` writes `scopes.sorted()`
    /// (`OAuthControlStore.swift:2233-2240`). Pin it so the difference is a
    /// recorded consequence of Swan's storage type rather than a surprise at the
    /// first duplicate-carrying client.
    func testDuplicateScopeTokensCollapseInSwanUnlikeUpstream() throws {
        let corpus = try UpstreamScopeCorpus.load()
        let row = try XCTUnwrap(corpus.strings.first { $0.input == "atproto atproto" })
        XCTAssertEqual(row.normalized, "atproto atproto", "upstream preserves the duplicate")

        let permissions = SwanScopePermissions(rawScopes: ["atproto", "atproto"], subject: nil)
        XCTAssertEqual(permissions.rawScopes, ["atproto"], "Swan's Set storage collapses it")
    }

    // MARK: - `matches`: the eight representative grants

    /// The 128-row match table, driven grant by grant.
    ///
    /// Upstream's `ScopePermissions` carries **no subject**, so this constructs
    /// Swan's facade with `subject: nil` to compare like with like. That is also
    /// the fail-closed shape: an unresolved `self` matches nothing
    /// (`space_permission.rs:1574-1584`, §6.4's fail-closed corollary), which is
    /// exactly upstream's behaviour when it cannot resolve one either.
    ///
    /// Blocked while the corpus's `matches` section is defective — see
    /// `UpstreamScopeCorpusIntegrityTests.testMatchesSectionIsAUsableOracle`.
    /// This test does not silently skip in that state: a suite that goes green
    /// because its oracle is broken is worse than one that is red.
    func testMatchOutcomesAgreeWithUpstreamForEveryGrant() throws {
        let corpus = try UpstreamScopeCorpus.load()
        guard case .usable = MatchesSectionHealth.assess(corpus) else {
            XCTFail(matchesSectionDefectExplanation)
            return
        }
        for (name, grant) in corpus.orderedGrants {
            let permissions = SwanScopePermissions(
                rawScopes: Set(grant.scope.split(separator: " ").map(String.init)),
                subject: nil
            )
            for outcome in grant.outcomes.repo {
                guard let expected = outcome.allowed,
                      let action = RepoAction(rawValue: outcome.arg.action)
                else { continue }
                XCTAssertEqual(
                    permissions.allowsRepo(
                        .init(collection: outcome.arg.collection, action: action)
                    ),
                    expected,
                    "\(name): repo \(outcome.arg)"
                )
            }
            for outcome in grant.outcomes.blob {
                guard let expected = outcome.allowed else { continue }
                XCTAssertEqual(
                    permissions.allowsBlob(.init(mime: outcome.arg.mime)),
                    expected,
                    "\(name): blob \(outcome.arg)"
                )
            }
            for outcome in grant.outcomes.rpc {
                guard let expected = outcome.allowed else { continue }
                XCTAssertEqual(
                    permissions.allowsRPC(.init(lxm: outcome.arg.lxm, aud: outcome.arg.aud)),
                    expected,
                    "\(name): rpc \(outcome.arg)"
                )
            }
            for outcome in grant.outcomes.identity {
                guard let expected = outcome.allowed,
                      let attr = IdentityAttribute(rawValue: outcome.arg.attr)
                else { continue }
                XCTAssertEqual(
                    permissions.allowsIdentity(.init(attr: attr)),
                    expected,
                    "\(name): identity \(outcome.arg)"
                )
            }
            for outcome in grant.outcomes.account {
                guard let expected = outcome.allowed,
                      let attr = AccountAttribute(rawValue: outcome.arg.attr),
                      let action = AccountAction(rawValue: outcome.arg.action)
                else { continue }
                XCTAssertEqual(
                    permissions.allowsAccount(.init(attr: attr, action: action)),
                    expected,
                    "\(name): account \(outcome.arg)"
                )
            }
            for outcome in grant.outcomes.space {
                guard let expected = outcome.allowed,
                      let operation = Self.spaceOperation(forCorpusAction: outcome.arg.action)
                else { continue }
                XCTAssertEqual(
                    permissions.allowsSpace(
                        .init(
                            type: outcome.arg.type,
                            authority: outcome.arg.authority,
                            skey: outcome.arg.skey,
                            operation: operation
                        )
                    ),
                    expected,
                    "\(name): space \(outcome.arg)"
                )
            }
        }
    }

    /// The corpus's `space` checks carry `{type, authority, skey, action}` and no
    /// `collection`, so a write action in that table is not expressible as a
    /// `SpaceScopeTarget`: §5.6.2 makes `collection` non-optional in the write
    /// arm, following upstream's own discriminated union
    /// (`space-permission.ts:70-74`). Those rows are skipped by the driver above,
    /// and this test records that they are skipped — an unrecorded skip is a
    /// coverage hole nobody can find later.
    func testCorpusSpaceWriteRowsAreNotExpressibleAsTargets() throws {
        let corpus = try UpstreamScopeCorpus.load()
        let skipped = corpus.orderedGrants.flatMap { _, grant in
            grant.outcomes.space.map(\.arg.action).filter { Self.spaceOperation(forCorpusAction: $0) == nil }
        }
        XCTAssertEqual(
            Set(skipped),
            ["delete"],
            """
            The corpus's space checks include a write action with no `collection`. \
            Upstream's own type makes `collection` non-optional in the write arm, \
            so that row was generated through erased types and asserts nothing \
            usable. Regenerate the corpus with a `collection` on every write check \
            to close this hole.
            """
        )
    }

    private static func spaceOperation(
        forCorpusAction action: String
    ) -> SpaceScopeTarget.Operation? {
        switch action {
        case "read": .read
        case "read_self": .readSelf
        default: nil  // write actions need a collection the corpus does not carry
        }
    }

    // MARK: - `didRefs`: the `isAtprotoDidRefAbsolute` truth table

    /// 13 rows (§9-D13). The validator is a port of `@atproto/did`, added as a
    /// SEPARATE predicate — the generic DID validator must not be mutated to
    /// carry the method allow-list or the mandatory fragment.
    func testAtprotoDIDRefTruthTableMatchesUpstream() throws {
        let corpus = try UpstreamScopeCorpus.load()
        for row in corpus.didRefs {
            XCTAssertEqual(
                AtprotoSyntax.isValidAtprotoDIDRefAbsolute(row.input),
                row.isAtprotoDidRefAbsolute,
                "isAtprotoDidRefAbsolute diverges for \(row.input.debugDescription)"
            )
        }
    }

    /// The two halves of the truth table that a reconstruction gets wrong, named
    /// so a regression points at the reason rather than at a row index: stricter
    /// than "valid DID + non-empty fragment" on methods and on `did:web` paths,
    /// looser on the fragment charset (RFC 3986 `pchar` plus `/`, `?` and
    /// percent escapes).
    func testDIDRefStrictnessIsAsymmetricAsUpstream() throws {
        let corpus = try UpstreamScopeCorpus.load()
        func expectation(_ input: String) throws -> Bool {
            try XCTUnwrap(corpus.didRefs.first { $0.input == input }).isAtprotoDidRefAbsolute
        }
        // Stricter: method allow-list is plc+web only; did:web takes no path.
        XCTAssertFalse(try expectation("did:example:456#service_id"))
        XCTAssertFalse(try expectation("did:web:example.com:path#bsky_fg"))
        // Looser: `/`, `?` and `%20` are all legal fragment bytes; a raw SPACE is not.
        XCTAssertTrue(try expectation("did:plc:z72i7hdynmk6r22z27h6tvur#has/slash"))
        XCTAssertTrue(try expectation("did:plc:z72i7hdynmk6r22z27h6tvur#has?question"))
        XCTAssertTrue(try expectation("did:plc:z72i7hdynmk6r22z27h6tvur#has%20escape"))
        XCTAssertFalse(try expectation("did:plc:z72i7hdynmk6r22z27h6tvur#has space"))
        // And the whole table is driven above; these six are the named arms.
        for input in [
            "did:example:456#service_id", "did:web:example.com:path#bsky_fg",
            "did:plc:z72i7hdynmk6r22z27h6tvur#has/slash",
            "did:plc:z72i7hdynmk6r22z27h6tvur#has?question",
            "did:plc:z72i7hdynmk6r22z27h6tvur#has%20escape",
            "did:plc:z72i7hdynmk6r22z27h6tvur#has space",
        ] {
            XCTAssertEqual(
                AtprotoSyntax.isValidAtprotoDIDRefAbsolute(input),
                try expectation(input),
                input
            )
        }
    }

    // MARK: - `encoders`: the two encoders §4.5 forbids unifying

    /// 11 rows, per character. `encodeURIComponent` (positional) and the
    /// `application/x-www-form-urlencoded` serialiser (query value) differ on
    /// exactly two of them, and both differences are load-bearing.
    func testBothEncodersMatchTheirJavaScriptCounterpartsByteForByte() throws {
        let corpus = try UpstreamScopeCorpus.load()
        for row in corpus.encoders {
            XCTAssertEqual(
                ScopeStringSyntax.encodeURIComponent(row.raw),
                row.encodeURIComponent,
                "encodeURIComponent diverges for \(row.raw.debugDescription)"
            )
            XCTAssertEqual(
                ScopeStringSyntax.encodeFormComponent(row.raw),
                row.urlSearchParams,
                "form encoder diverges for \(row.raw.debugDescription)"
            )
        }
    }

    /// The two rows where the encoders disagree, asserted from the fixture and
    /// named — unifying them is the "simplification" §4.5 exists to forbid.
    func testTheTwoEncodersDisagreeExactlyWhereUpstreamDoes() throws {
        let corpus = try UpstreamScopeCorpus.load()
        let disagreements = corpus.encoders
            .filter { $0.encodeURIComponent != $0.urlSearchParams }
            .map(\.raw)
        XCTAssertEqual(
            Set(disagreements),
            ["a~b", "a b"],
            """
            `~` stays raw in a positional and becomes `%7E` in a query value; \
            SPACE becomes `%20` in a positional and `+` in a query value. Those \
            are the only two, and they are why the encoders must not be unified \
            (§4.5). Foundation's `addingPercentEncoding` gets the SPACE case wrong \
            in the query direction.
            """
        )
    }
}
