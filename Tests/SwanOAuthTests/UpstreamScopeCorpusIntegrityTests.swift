import Foundation
import XCTest

/// Asserts the golden corpus is loadable, pinned, complete, and usable as an
/// oracle — **before** any suite drives Swift against it.
///
/// These tests depend on no production symbol. They are the ones that can run
/// while the grammar, persistence and enforcement lanes are still landing, and
/// they are the ones that catch the failure the corpus mechanism exists to
/// prevent: a fixture that silently stops describing upstream.
final class UpstreamScopeCorpusIntegrityTests: XCTestCase, @unchecked Sendable {
    // MARK: - The corpus is present and pinned

    func testCorpusLoadsFromTheTestBundle() throws {
        let corpus = try UpstreamScopeCorpus.load()
        XCTAssertFalse(corpus.values.isEmpty)
        XCTAssertFalse(corpus.strings.isEmpty)
        XCTAssertFalse(corpus.matches.isEmpty)
        XCTAssertFalse(corpus.didRefs.isEmpty)
        XCTAssertFalse(corpus.encoders.isEmpty)
    }

    func testCorpusIsPinnedToTheSealedUpstreamCommit() throws {
        let corpus = try UpstreamScopeCorpus.load()
        XCTAssertEqual(
            corpus.referenceCommit,
            UpstreamScopeCorpus.pinnedReferenceCommit,
            """
            The corpus records a different upstream commit than the spec seals \
            (§7.1a). Moving the pin is a design change, not a drift fix: \
            re-verify every §7.3 divergence-fence row before accepting it.
            """
        )
        XCTAssertTrue(
            corpus.source.contains("oauth-scopes"),
            "corpus provenance line no longer names the generating package"
        )
    }

    /// The corpus is only as good as its coverage. These counts are the shape
    /// §7.1a and the lane brief describe; a truncated fixture would otherwise
    /// pass every driver vacuously.
    func testCorpusSectionsCarryTheirDeclaredRowCounts() throws {
        let corpus = try UpstreamScopeCorpus.load()
        XCTAssertEqual(corpus.values.count, 52, "per-value parse + canonical rows")
        XCTAssertEqual(corpus.strings.count, 6, "whole-scope-string normalisation rows")
        XCTAssertEqual(corpus.matches.count, 8, "representative grants")
        XCTAssertEqual(corpus.didRefs.count, 13, "isAtprotoDidRefAbsolute truth-table rows")
        XCTAssertEqual(corpus.encoders.count, 11, "encodeURIComponent vs URLSearchParams rows")
    }

    /// bulleted.app's five scopes (§1, §7.4) must each be present in the corpus,
    /// or the acceptance test's Stage-1 expectations would be hand-written after
    /// all.
    func testCorpusCoversAllFiveBulletedAppScopes() throws {
        let corpus = try UpstreamScopeCorpus.load()
        let inputs = Set(corpus.values.map(\.input))
        for scope in BulletedAppScopes.all {
            XCTAssertTrue(
                inputs.contains(scope),
                "bulleted.app scope not covered by the golden corpus: \(scope)"
            )
        }
    }

    // MARK: - Internal consistency

    /// `isAtprotoOauthScope` and "the normaliser returned a value" are two
    /// different upstream predicates. Where they disagree, a Swift port that
    /// conflates them would be provably wrong — so pin that they agree across
    /// the whole corpus, and let a future regeneration break this if they ever
    /// stop agreeing.
    func testRecognitionAndParseabilityAgreeAcrossTheCorpus() throws {
        let corpus = try UpstreamScopeCorpus.load()
        for value in corpus.values {
            XCTAssertEqual(
                value.isAtprotoOauthScope,
                value.parses,
                "recognition/parse disagreement on \(value.input.debugDescription)"
            )
        }
    }

    /// §4.5's pinned lossiness. Every parsing row in the current corpus round
    /// trips; the moment one does not, the canonical form is a string that
    /// cannot be re-parsed and the §9-D7 subset check must fall back to raw
    /// comparison for it. Surface it as a named list rather than a silent pass.
    func testRoundTripInstabilityIsEnumerated() throws {
        let corpus = try UpstreamScopeCorpus.load()
        let unstable = corpus.values.filter { $0.parses && $0.roundTripStable == false }
        XCTAssertEqual(
            unstable.map(\.input),
            [],
            """
            Corpus rows whose canonical form does not re-parse. This is not \
            automatically a failure — §4.5 reproduces upstream's `+` lossiness \
            deliberately — but each one constrains §9-D7's registered-vs-requested \
            subset check, which must compare those scopes as RAW BYTES on both \
            sides rather than treating the registered value as absent. Record any \
            new row here before changing this expectation.
            """
        )
    }

    /// The corpus's own README calls this out and §9-D23 turns on it: canonical
    /// serialisation DELETES a parameter whose value equals its default. Pin it
    /// straight from the fixture, because it is the mechanism that makes
    /// provenance unrecoverable from a persisted string.
    func testCanonicalSerialisationDestroysDefaultEqualParameters() throws {
        let corpus = try UpstreamScopeCorpus.load()
        func canonical(of input: String) throws -> String? {
            try XCTUnwrap(corpus.values.first { $0.input == input }, "corpus row missing: \(input)")
                .canonical
        }
        // A STATED `skey=*` and a STATED `authority=self` both vanish.
        XCTAssertEqual(try canonical(of: "space:com.example.group?skey=*"), "space:com.example.group")
        XCTAssertEqual(try canonical(of: "space:com.example.group?authority=self"), "space:com.example.group")
        // ... and a bare grant is byte-identical to both of them. So no reader of
        // the canonical string can tell a stated `skey=*` from a defaulted one:
        // provenance must be persisted beside the grant (§9-D23), never
        // reconstructed from it.
        XCTAssertEqual(try canonical(of: "space:com.example.group"), "space:com.example.group")
    }

    // MARK: - The `matches` section, and why it is not currently an oracle

    /// **BLOCKING FINDING.** The `matches` section of the checked-in corpus is
    /// not a truth table: every outcome in it is `false`.
    ///
    /// This test fails loudly, with the diagnosis, rather than letting the
    /// conformance driver pin 128 false outcomes as upstream behaviour. It needs
    /// no edit once the corpus is regenerated with the fixed generator — it flips
    /// green on its own, and `UpstreamScopeMatchConformanceTests` starts
    /// asserting real outcomes at the same moment.
    ///
    /// Evidence that this is a generator defect and not upstream behaviour, all
    /// independent of each other:
    ///
    ///  * `repo:app.bsky.feed.post?action=create` denies
    ///    `{create, app.bsky.feed.post}` — upstream's own
    ///    `repo-permission.test.ts` asserts that pair is allowed, and §7.2.4 row
    ///    1 ports it.
    ///  * `space:com.example.group?authority=did:plc:z72…&skey=default&action=read`,
    ///    fully concrete in every dimension, denies exactly that tuple with
    ///    `action=read` — §7.2.4 row 5 says true.
    ///  * `blob:image/*` denies `image/png` (§5.2), `identity:handle` denies
    ///    `{attr:handle}` (§5.3), `repo:*` denies every collection (§5.4).
    ///  * 128 of 128 outcomes false across eight deliberately-varied grants is
    ///    not a shape any real matcher produces.
    ///
    /// Cause, in `Scripts/upstream-scope-goldens/generate.mjs`: the permissions
    /// value was built as `new ScopePermissions(new ScopesSet(scopeString))`.
    /// `ScopesSet extends Set<string>`, so a whole space-delimited string handed
    /// to it is iterated character by character. `ScopePermissions`'s own
    /// constructor is the one that splits on SPACE, so the correct call is
    /// `new ScopePermissions(scopeString)`. The generator is fixed in this
    /// change; regenerating the fixture needs a full `bddc99fb` checkout
    /// (`Scripts/upstream-scope-goldens/verify-corpus-zero-diff.sh`).
    func testMatchesSectionIsAUsableOracle() throws {
        let corpus = try UpstreamScopeCorpus.load()
        switch MatchesSectionHealth.assess(corpus) {
        case .usable:
            break
        case let .uniformlyFalse(count):
            XCTFail("\(count) of \(count) outcomes are false.\n\n\(matchesSectionDefectExplanation)")
        }
    }

    /// The corpus's `matches` grants must at least still be the eight the spec's
    /// acceptance work references, so a regeneration that silently narrowed the
    /// grant table is visible.
    func testMatchesSectionCoversTheEightRepresentativeGrants() throws {
        let corpus = try UpstreamScopeCorpus.load()
        XCTAssertEqual(
            corpus.orderedGrants.map(\.name),
            [
                "atprotoOnly", "bareSpace", "blobImages", "bulleted",
                "identityHandle", "repoNarrow", "repoWide", "spaceReadOnly",
            ]
        )
        let bulleted = try XCTUnwrap(corpus.matches["bulleted"])
        XCTAssertEqual(
            bulleted.scope,
            BulletedAppScopes.all.joined(separator: " "),
            "the corpus's bulleted grant must be exactly the five scopes of §1, in order"
        )
    }

    // MARK: - §7.6 step 7: the regeneration gate

    /// The gate itself is a script, because regeneration needs a full upstream
    /// checkout, `npm`, and a TypeScript-transform-capable `node` — none of which
    /// belong inside a unit test. What the test owns is that the script exists,
    /// is executable, and pins the same commit the fixture does; a gate nobody
    /// can run is not a gate.
    func testRegenerationGateScriptExistsAndPinsTheSameCommit() throws {
        let script = UpstreamScopeCorpus.generatorDirectoryURL
            .appending(path: "verify-corpus-zero-diff.sh")
        XCTAssertTrue(
            FileManager.default.isExecutableFile(atPath: script.path),
            "§7.6 step 7 gate missing or not executable: \(script.path)"
        )
        let source = try String(contentsOf: script, encoding: .utf8)
        XCTAssertTrue(
            source.contains(UpstreamScopeCorpus.pinnedReferenceCommit),
            "the gate script pins a different commit than the fixture"
        )
        let generator = UpstreamScopeCorpus.generatorDirectoryURL.appending(path: "generate.mjs")
        let generatorSource = try String(contentsOf: generator, encoding: .utf8)
        XCTAssertTrue(
            generatorSource.contains(UpstreamScopeCorpus.pinnedReferenceCommit),
            "the generator pins a different commit than the fixture"
        )
        // The defect above must not be able to come back silently.
        XCTAssertFalse(
            generatorSource.contains("new ScopesSet("),
            """
            generate.mjs is constructing a ScopesSet by hand again. That is the \
            character-by-character defect described in \
            testMatchesSectionIsAUsableOracle: pass the scope string to \
            `new ScopePermissions(...)` instead.
            """
        )
    }

    /// Runs the real gate when an upstream checkout is available. Opt-in via
    /// `SWAN_UPSTREAM_ATPROTO`, because CI machines without the tree would
    /// otherwise fail on a missing dependency rather than on corpus drift —
    /// and a gate that fails for the wrong reason gets disabled.
    func testCorpusRegeneratesToAZeroDiffWhenUpstreamIsAvailable() throws {
        guard let upstream = ProcessInfo.processInfo.environment["SWAN_UPSTREAM_ATPROTO"],
              !upstream.isEmpty
        else {
            throw XCTSkip(
                """
                SWAN_UPSTREAM_ATPROTO not set — the §7.6 step 7 zero-diff gate did \
                NOT run. Run it before merge: \
                SWAN_UPSTREAM_ATPROTO=<full checkout of \
                \(UpstreamScopeCorpus.pinnedReferenceCommit)> \
                Scripts/upstream-scope-goldens/verify-corpus-zero-diff.sh
                """
            )
        }
        let script = UpstreamScopeCorpus.generatorDirectoryURL
            .appending(path: "verify-corpus-zero-diff.sh")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = [script.path]
        var environment = ProcessInfo.processInfo.environment
        environment["SWAN_UPSTREAM_ATPROTO"] = upstream
        process.environment = environment
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        XCTAssertEqual(
            process.terminationStatus,
            0,
            "corpus regeneration is not a zero diff:\n\(String(decoding: data, as: UTF8.self))"
        )
    }
}

/// bulleted.app's five real scopes (§1, §7.4). Declared once so the corpus
/// integrity suite, the conformance suite and the HTTP acceptance test cannot
/// drift into three slightly different lists.
enum BulletedAppScopes {
    static let base = "atproto"
    static let includeAuthFull = "include:app.bulleted.authFull"
    static let blobImages = "blob:image/*"
    static let includeSpaceAccess = "include:app.bulleted.spaceAccess"
    static let space =
        "space:app.bulleted.space?manage=create&manage=update&manage=delete&action=read_self"

    /// Order matters: this is the order the client's `scope` string carries them.
    static let all = [base, includeAuthFull, blobImages, includeSpaceAccess, space]

    /// The canonical form the `space:` scope must take after parse +
    /// re-serialisation. `manage` follows `SPACE_MANAGE_OPS` order
    /// (`create, update, delete`) and `action` precedes `manage` by schema
    /// declaration order — NOT input order (§7.4 Stage 1). Taken from the corpus
    /// at runtime by the conformance suite; repeated here only for the HTTP
    /// acceptance test, which asserts it against a live token response.
    static let canonicalSpace =
        "space:app.bulleted.space?action=read_self&manage=create&manage=update&manage=delete"

    static let spaceType = "app.bulleted.space"
}
