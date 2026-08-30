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
        XCTAssertEqual(corpus.values.count, 62, "per-value parse + canonical rows")
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

    /// The corpus must keep at least one example of each rejection class the
    /// grammar can produce, plus a positive control for the decoding path.
    ///
    /// This exists because the corpus shipped for a while with **zero** examples
    /// of two whole classes — positional+named conflict and repeated
    /// single-valued parameter — so no corpus-driven test could reach either
    /// branch, and the absence was invisible from a green run. A regeneration
    /// that silently drops them would recreate exactly that hole.
    ///
    /// Asserted structurally (by shape of the input) rather than by literal
    /// string, so adding more examples of a class strengthens the corpus without
    /// touching this test.
    func testCorpusCoversEachRejectionClassAndTheDecodingPositiveControl() throws {
        let corpus = try UpstreamScopeCorpus.load()

        /// A parameter supplied both positionally and by name — forbidden by the
        /// schema (`parser.ts:124-127`).
        let positionalKeys = [
            "account": "attr", "identity": "attr", "repo": "collection",
            "rpc": "lxm", "blob": "accept", "space": "type", "include": "nsid",
        ]
        let conflicts = corpus.values.filter { value in
            let input = value.input
            guard let questionMark = input.firstIndex(of: "?") else { return false }
            let head = String(input[input.startIndex ..< questionMark])
            guard let colon = head.firstIndex(of: ":"), head.index(after: colon) < head.endIndex,
                  let key = positionalKeys[String(head[head.startIndex ..< colon])]
            else { return false }
            let query = input[input.index(after: questionMark)...]
            return query.split(separator: "&").contains { $0.hasPrefix("\(key)=") }
        }
        XCTAssertFalse(
            conflicts.isEmpty,
            "no positional+named conflict vector — that rejection branch is unreachable from the corpus"
        )
        for value in conflicts {
            XCTAssertFalse(value.parses, "a positional+named conflict must be rejected: \(value.input)")
        }

        /// A single-valued parameter given more than once — `getSingle` returns
        /// null (`syntax-string.ts:18-23`) and the schema rejects on null
        /// (`parser.ts:121-122`). This is the tri-state that must not collapse
        /// into `String?`.
        ///
        /// `action` and `collection` are deliberately absent: they are `.multiple`
        /// arity, so repeating them is legal and the corpus carries such a row
        /// (`account:email?action=read&action=manage`) as the contrast.
        let singleValued: Set<String> = ["authority", "skey", "type", "attr", "aud", "nsid"]
        let repeats = corpus.values.filter { value in
            guard let questionMark = value.input.firstIndex(of: "?") else { return false }
            let keys = value.input[value.input.index(after: questionMark)...]
                .split(separator: "&")
                .compactMap { $0.split(separator: "=").first.map(String.init) }
                .filter(singleValued.contains)
            return Set(keys).count < keys.count
        }
        XCTAssertFalse(
            repeats.isEmpty,
            "no repeated single-valued parameter vector — that rejection branch is unreachable"
        )
        for value in repeats {
            XCTAssertFalse(
                value.parses,
                "a repeated single-valued parameter must be rejected: \(value.input)"
            )
        }

        /// Positive control. Every row above is rejection-shaped, and a corpus
        /// that only ever grows richer in rejections tests less than it appears
        /// to. The positional is `decodeURIComponent`d
        /// (`syntax-string.ts:62-64`), so an escaped positional must DECODE and
        /// round-trip, not merely fail to explode.
        let escapedPositional = corpus.values.filter { value in
            guard let head = value.input.split(separator: "?").first else { return false }
            return head.contains("%")
        }
        XCTAssertFalse(
            escapedPositional.isEmpty,
            "no percent-escaped positional vector — the decode path has no positive control"
        )
        XCTAssertTrue(
            escapedPositional.contains { $0.parses && $0.roundTripStable == true },
            """
            every percent-escaped positional in the corpus is a rejection. At \
            least one must DECODE and round-trip stably, or this class only \
            proves the parser can say no.
            """
        )
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

    // MARK: - Task 16: Supply chain and maintenance integrity

    func testDockerContextExcludesWebBuildArtifactsAndCaches() throws {
        let repoRoot = UpstreamScopeCorpus.generatorDirectoryURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let dockerignoreURL = repoRoot.appending(path: "Dockerfile.dockerignore")
        let content = try String(contentsOf: dockerignoreURL, encoding: .utf8)
        let rules = content.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }

        func isIgnored(_ candidate: String) -> Bool {
            var ignored = false
            for rule in rules {
                let negated = rule.hasPrefix("!")
                var pattern = negated ? String(rule.dropFirst()) : rule
                if pattern.hasPrefix("/") { pattern = String(pattern.dropFirst()) }
                if pattern.hasSuffix("/") { pattern += "**" }
                if matchesGlob(candidate: candidate, pattern: pattern) {
                    ignored = !negated
                }
            }
            return ignored
        }
        func matchesGlob(candidate: String, pattern: String) -> Bool {
            if pattern == "**" { return true }
            if pattern == candidate { return true }
            if pattern.hasPrefix("**/") {
                let suffix = String(pattern.dropFirst(3))
                if suffix.hasSuffix("/**") {
                    let middle = String(suffix.dropLast(3))
                    return candidate.contains("/\(middle)/") || candidate.hasPrefix("\(middle)/") || candidate.hasSuffix("/\(middle)") || candidate == middle
                }
                return candidate.hasSuffix("/\(suffix)") || candidate == suffix || candidate.contains("/\(suffix)/")
            }
            if pattern.hasSuffix("/**") {
                let prefix = String(pattern.dropLast(3))
                return candidate.hasPrefix("\(prefix)/") || candidate == prefix
            }
            if pattern.hasSuffix("/*") {
                let prefix = String(pattern.dropLast(2))
                return candidate.hasPrefix("\(prefix)/") && !candidate.dropFirst(prefix.count + 1).contains("/")
            }
            if pattern.hasPrefix("*.") {
                let ext = String(pattern.dropFirst(1))
                return candidate.hasSuffix(ext)
            }
            return candidate == pattern
        }

        XCTAssertTrue(isIgnored("Swan/web/node_modules"), "Swan/web/node_modules must be ignored")
        XCTAssertTrue(isIgnored("Swan/web/node_modules/foo.js"), "Swan/web/node_modules/** must be ignored")
        XCTAssertTrue(isIgnored("Swan/web/.svelte-kit"), "Swan/web/.svelte-kit must be ignored")
        XCTAssertTrue(isIgnored("Swan/web/.svelte-kit/tsconfig.json"), "Swan/web/.svelte-kit/** must be ignored")
        XCTAssertTrue(isIgnored("Swan/web/build"), "Swan/web/build must be ignored")
        XCTAssertTrue(isIgnored("Swan/web/build/index.js"), "Swan/web/build/** must be ignored")
        XCTAssertTrue(isIgnored("Swan/web/test-results"), "Swan/web/test-results must be ignored")
        XCTAssertTrue(isIgnored("Swan/web/test-results/report.json"), "Swan/web/test-results/** must be ignored")
        XCTAssertTrue(isIgnored("Swan/web/playwright-report"), "Swan/web/playwright-report must be ignored")
        XCTAssertTrue(isIgnored("Swan/web/playwright-report/index.html"), "Swan/web/playwright-report/** must be ignored")

        XCTAssertFalse(isIgnored("Swan/web/package.json"), "Swan/web/package.json must not be ignored")
        XCTAssertFalse(isIgnored("Swan/web/package-lock.json"), "Swan/web/package-lock.json must not be ignored")
        XCTAssertFalse(isIgnored("Swan/web/src/app.html"), "Swan/web/src/app.html must not be ignored")
        XCTAssertFalse(isIgnored("Swan/Sources/SwanHTTP/SwanHTTP.swift"), "Swan/Sources must not be ignored")
    }

    func testBrowserCSSToolingPackageHasPinnedLockfileAndSuppressesScripts() throws {
        let repoRoot = UpstreamScopeCorpus.generatorDirectoryURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let packageDir = repoRoot.appending(path: "Scripts/browser-css-tooling")
        let packageJSONURL = packageDir.appending(path: "package.json")
        let packageLockURL = packageDir.appending(path: "package-lock.json")

        XCTAssertTrue(FileManager.default.fileExists(atPath: packageJSONURL.path), "browser-css-tooling package.json missing")
        XCTAssertTrue(FileManager.default.fileExists(atPath: packageLockURL.path), "browser-css-tooling package-lock.json missing")

        let pkgData = try Data(contentsOf: packageJSONURL)
        let pkgJSON = try JSONSerialization.jsonObject(with: pkgData) as? [String: Any]
        let deps = pkgJSON?["dependencies"] as? [String: String] ?? [:]
        XCTAssertEqual(deps["tailwindcss"], "4.3.3", "tailwindcss must be pinned to 4.3.3")
        XCTAssertEqual(deps["@tailwindcss/cli"], "4.3.3", "@tailwindcss/cli must be pinned to 4.3.3")
        XCTAssertEqual(deps["daisyui"], "5.7.19", "daisyui must be pinned to 5.7.19")

        let tempDir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try FileManager.default.copyItem(at: packageJSONURL, to: tempDir.appending(path: "package.json"))
        try FileManager.default.copyItem(at: packageLockURL, to: tempDir.appending(path: "package-lock.json"))

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        proc.arguments = ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"]
        proc.currentDirectoryURL = tempDir
        let output = Pipe()
        proc.standardOutput = output
        proc.standardError = output
        try proc.run()
        proc.waitUntilExit()
        XCTAssertEqual(proc.terminationStatus, 0, "npm ci --ignore-scripts failed in temporary directory")
    }

    func testUpstreamScopeToolingPackageHasPinnedLockfileAndInstallsCleanly() throws {
        let repoRoot = UpstreamScopeCorpus.generatorDirectoryURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let packageDir = repoRoot.appending(path: "Scripts/upstream-scope-goldens")
        let packageJSONURL = packageDir.appending(path: "package.json")
        let packageLockURL = packageDir.appending(path: "package-lock.json")

        XCTAssertTrue(FileManager.default.fileExists(atPath: packageJSONURL.path), "upstream-scope-goldens package.json missing")
        XCTAssertTrue(FileManager.default.fileExists(atPath: packageLockURL.path), "upstream-scope-goldens package-lock.json missing")

        let pkgData = try Data(contentsOf: packageJSONURL)
        let pkgJSON = try JSONSerialization.jsonObject(with: pkgData) as? [String: Any]
        let deps = pkgJSON?["dependencies"] as? [String: String] ?? [:]
        XCTAssertEqual(deps["zod"], "3.24.2", "zod must be pinned to 3.24.2")
        XCTAssertEqual(deps["iso-datestring-validator"], "2.2.2", "iso-datestring-validator must be pinned to 2.2.2")
        XCTAssertEqual(deps["multiformats"], "13.4.2", "multiformats must be pinned to 13.4.2")

        let tempDir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try FileManager.default.copyItem(at: packageJSONURL, to: tempDir.appending(path: "package.json"))
        try FileManager.default.copyItem(at: packageLockURL, to: tempDir.appending(path: "package-lock.json"))

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        proc.arguments = ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"]
        proc.currentDirectoryURL = tempDir
        let output = Pipe()
        proc.standardOutput = output
        proc.standardError = output
        try proc.run()
        proc.waitUntilExit()
        XCTAssertEqual(proc.terminationStatus, 0, "npm ci --ignore-scripts failed in temporary directory")
    }

    func testRegenerationGateRejectsWrongRevisionBeforeNpmOrNode() throws {
        let script = UpstreamScopeCorpus.generatorDirectoryURL
            .appending(path: "verify-corpus-zero-diff.sh")
        let tempRepo = FileManager.default.temporaryDirectory.appending(path: "test-fake-atproto-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempRepo, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempRepo) }

        let initProc = Process()
        initProc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        initProc.arguments = ["git", "-C", tempRepo.path, "init", "-b", "main"]
        try initProc.run()
        initProc.waitUntilExit()

        let pkgPath = tempRepo.appending(path: "packages/oauth/oauth-scopes/src/scopes")
        try FileManager.default.createDirectory(at: pkgPath, withIntermediateDirectories: true)
        try "export const space = true;\n".write(to: pkgPath.appending(path: "space-permission.ts"), atomically: true, encoding: .utf8)

        let addProc = Process()
        addProc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        addProc.arguments = ["git", "-C", tempRepo.path, "add", "."]
        try addProc.run()
        addProc.waitUntilExit()

        let commitProc = Process()
        commitProc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        commitProc.arguments = ["git", "-C", tempRepo.path, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "wrong commit"]
        try commitProc.run()
        commitProc.waitUntilExit()

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/bash")
        proc.arguments = [script.path]
        var env = ProcessInfo.processInfo.environment
        env["SWAN_UPSTREAM_ATPROTO"] = tempRepo.path
        proc.environment = env
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        try proc.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()

        XCTAssertNotEqual(proc.terminationStatus, 0, "verify-corpus-zero-diff.sh must reject non-pinned git commit")
        let outputStr = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(outputStr.contains("bddc99fb") || outputStr.contains("commit") || outputStr.contains("HEAD"), "output must describe commit mismatch: \(outputStr)")
    }

    func testRegenerationGateRejectsDirtyWorkingTree() throws {
        let script = UpstreamScopeCorpus.generatorDirectoryURL
            .appending(path: "verify-corpus-zero-diff.sh")
        let tempRepo = FileManager.default.temporaryDirectory.appending(path: "test-fake-atproto-dirty-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempRepo, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempRepo) }

        let initProc = Process()
        initProc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        initProc.arguments = ["git", "-C", tempRepo.path, "init", "-b", "main"]
        try initProc.run()
        initProc.waitUntilExit()

        let pkgPath = tempRepo.appending(path: "packages/oauth/oauth-scopes/src/scopes")
        try FileManager.default.createDirectory(at: pkgPath, withIntermediateDirectories: true)
        try "export const space = true;\n".write(to: pkgPath.appending(path: "space-permission.ts"), atomically: true, encoding: .utf8)

        try "untracked\n".write(to: tempRepo.appending(path: "untracked.txt"), atomically: true, encoding: .utf8)

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/bash")
        proc.arguments = [script.path]
        var env = ProcessInfo.processInfo.environment
        env["SWAN_UPSTREAM_ATPROTO"] = tempRepo.path
        proc.environment = env
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        try proc.run()
        _ = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()

        XCTAssertNotEqual(proc.terminationStatus, 0, "verify-corpus-zero-diff.sh must reject dirty git repository")
    }

    func testRegenerationGateRejectsSymlinksInCopiedPackageTrees() throws {
        let script = UpstreamScopeCorpus.generatorDirectoryURL
            .appending(path: "verify-corpus-zero-diff.sh")
        let tempRepo = FileManager.default.temporaryDirectory.appending(path: "test-fake-atproto-symlink-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempRepo, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempRepo) }

        let didPkg = tempRepo.appending(path: "packages/did")
        try FileManager.default.createDirectory(at: didPkg, withIntermediateDirectories: true)
        let oauthPkg = tempRepo.appending(path: "packages/oauth/oauth-scopes/src/scopes")
        try FileManager.default.createDirectory(at: oauthPkg, withIntermediateDirectories: true)
        try "export const space = true;\n".write(to: oauthPkg.appending(path: "space-permission.ts"), atomically: true, encoding: .utf8)

        try FileManager.default.createSymbolicLink(at: didPkg.appending(path: "link.ts"), withDestinationURL: URL(fileURLWithPath: "/etc/passwd"))

        let initProc = Process()
        initProc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        initProc.arguments = ["git", "-C", tempRepo.path, "init", "-b", "main"]
        try initProc.run()
        initProc.waitUntilExit()

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/bash")
        proc.arguments = [script.path]
        var env = ProcessInfo.processInfo.environment
        env["SWAN_UPSTREAM_ATPROTO"] = tempRepo.path
        proc.environment = env
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        try proc.run()
        _ = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()

        XCTAssertNotEqual(proc.terminationStatus, 0, "verify-corpus-zero-diff.sh must reject symlinks in package trees")
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
