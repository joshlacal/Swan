import Foundation
import XCTest

/// Typed decoding of `Fixtures/pinned-typescript-oauth-scopes.json`, the golden
/// corpus produced by running upstream's own `@atproto/oauth-scopes` unbuilt at
/// the pinned commit (§7.1a, `Scripts/upstream-scope-goldens/README.md`).
///
/// The corpus is the ORACLE for the grammar layer: where the spec's prose and
/// this file disagree about what a scope string parses or canonicalises to, the
/// fixture wins and the disagreement is a finding (operating instructions,
/// "Golden vectors, not transcription").
///
/// **Nothing here hand-copies a vector.** Every expectation reaching a Swift
/// assertion is decoded from the JSON, so a regenerated corpus changes the
/// tests' behaviour with no Swift edit. That is the whole mechanism: a
/// transcription error in a canonicalisation vector is invisible until a
/// client's registered scope stops matching its requested scope.
struct UpstreamScopeCorpus: Decodable, Sendable {
    /// The upstream commit the corpus was generated at. Pinned; a change here is
    /// a design event, not a drift fix (§7.6 step 7).
    static let pinnedReferenceCommit = "bddc99fb24c34b4078b9bf65837283f37b49ab66"

    let referenceCommit: String
    let source: String
    let nodeVersion: String
    let values: [Value]
    let strings: [ScopeString]
    let matches: [String: Grant]
    let didRefs: [DIDRef]
    let encoders: [Encoder]

    /// One scope value, run through `normalizeAtprotoOauthScopeValue`.
    struct Value: Decodable, Sendable {
        let input: String
        /// `isAtprotoOauthScope(input)` — upstream's recognition predicate.
        let isAtprotoOauthScope: Bool
        /// Canonical re-serialisation, or `nil` when upstream's parser returned
        /// `null` (its sole failure signal for the grammar layer).
        let canonical: String?
        /// Upstream threw rather than returning `null`. Distinct from `canonical
        /// == nil`: a throw is `decodeURIComponent`'s uncaught `URIError`
        /// (§4.4 positional column), not a parse rejection.
        let threw: String?
        /// `normalize(canonical) == canonical`. `nil` when the value did not
        /// parse. `false` pins an upstream lossiness Swan reproduces (§4.5).
        let roundTripStable: Bool?

        var parses: Bool { canonical != nil }
    }

    /// A whole space-delimited scope string through `normalizeAtprotoOauthScope`.
    struct ScopeString: Decodable, Sendable {
        let input: String
        let normalized: String
    }

    /// `ScopePermissions.allows*` outcomes for one representative grant.
    struct Grant: Decodable, Sendable {
        let scope: String
        let outcomes: Outcomes
    }

    struct Outcomes: Decodable, Sendable {
        let repo: [Outcome<RepoArg>]
        let blob: [Outcome<BlobArg>]
        let rpc: [Outcome<RPCArg>]
        let identity: [Outcome<IdentityArg>]
        let account: [Outcome<AccountArg>]
        let space: [Outcome<SpaceArg>]

        /// Every outcome in the grant, flattened, as `(family, description,
        /// allowed)`. Used by the corpus-health check, which has to reason about
        /// the whole table rather than one arm.
        var allAllowed: [Bool?] {
            repo.map(\.allowed) + blob.map(\.allowed) + rpc.map(\.allowed)
                + identity.map(\.allowed) + account.map(\.allowed) + space.map(\.allowed)
        }
    }

    struct Outcome<Argument: Decodable & Sendable>: Decodable, Sendable {
        let arg: Argument
        /// `nil` when the upstream call threw instead of returning a Bool.
        let allowed: Bool?
        let threw: String?
    }

    struct RepoArg: Decodable, Sendable {
        let action: String
        let collection: String
    }

    struct BlobArg: Decodable, Sendable {
        let mime: String
    }

    struct RPCArg: Decodable, Sendable {
        let aud: String
        let lxm: String
    }

    struct IdentityArg: Decodable, Sendable {
        let attr: String
    }

    struct AccountArg: Decodable, Sendable {
        let attr: String
        let action: String
    }

    struct SpaceArg: Decodable, Sendable {
        let type: String
        let authority: String
        let skey: String
        let action: String
    }

    /// `isAtprotoDidRefAbsolute` truth table (`packages/did/src/atproto.ts:230`).
    struct DIDRef: Decodable, Sendable {
        let input: String
        let isAtprotoDidRefAbsolute: Bool
    }

    /// `encodeURIComponent` vs `URLSearchParams`, per character — the two
    /// encoders §4.5 forbids unifying.
    struct Encoder: Decodable, Sendable {
        let raw: String
        /// JavaScript `encodeURIComponent(raw)`.
        let encodeURIComponent: String
        /// `new URLSearchParams([['x', raw]]).toString().slice(2)`.
        let urlSearchParams: String
    }

    /// Grants in a deterministic order. `matches` is a JSON object, so decoding
    /// order is not stable; every driver iterates this instead.
    var orderedGrants: [(name: String, grant: Grant)] {
        matches.keys.sorted().map { (name: $0, grant: matches[$0]!) }
    }
}

extension UpstreamScopeCorpus {
    /// Loads the corpus from the test bundle. `Package.swift:235` declares
    /// `resources: [.copy("Fixtures")]` for `SwanOAuthTests`, so the directory
    /// structure survives into the bundle and `subdirectory:` is required.
    static func load(
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> UpstreamScopeCorpus {
        let url = try XCTUnwrap(
            Bundle.module.url(
                forResource: "pinned-typescript-oauth-scopes",
                withExtension: "json",
                subdirectory: "Fixtures"
            ),
            "golden corpus missing from the SwanOAuthTests bundle",
            file: file,
            line: line
        )
        return try JSONDecoder().decode(UpstreamScopeCorpus.self, from: Data(contentsOf: url))
    }

    /// The on-disk fixture, for the regeneration gate (§7.6 step 7), which has
    /// to diff bytes rather than decoded values.
    static var sourceFixtureURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appending(path: "Fixtures/pinned-typescript-oauth-scopes.json")
    }

    static var generatorDirectoryURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appending(path: "Scripts/upstream-scope-goldens")
    }
}

// MARK: - Corpus health

/// Whether the corpus's `matches` section can be used as an oracle at all.
///
/// This exists because it turned out not to be usable, and a suite that drove
/// Swift against it would have pinned the defect as conformance. See
/// `UpstreamScopeCorpusIntegrityTests.testMatchesSectionIsAUsableOracle` for the
/// full evidence.
enum MatchesSectionHealth: Sendable, Equatable {
    case usable
    /// Every single outcome across every grant is `false`. Not a truth table:
    /// a grant of `repo:app.bsky.feed.post?action=create` denying
    /// `{create, app.bsky.feed.post}` contradicts upstream's own
    /// `repo-permission.test.ts`, and a fully-concrete `space:` grant denying
    /// its own exact tuple contradicts §7.2.4 row 5.
    case uniformlyFalse(outcomeCount: Int)

    static func assess(_ corpus: UpstreamScopeCorpus) -> MatchesSectionHealth {
        let all = corpus.orderedGrants.flatMap { $0.grant.outcomes.allAllowed }
        guard !all.isEmpty else { return .uniformlyFalse(outcomeCount: 0) }
        return all.allSatisfy { $0 == false }
            ? .uniformlyFalse(outcomeCount: all.count)
            : .usable
    }
}

/// The one-line explanation every blocked assertion prints, so a red run names
/// the cause instead of the symptom.
let matchesSectionDefectExplanation = """
    GOLDEN CORPUS DEFECT (blocking, reported to lane lead): the `matches` section \
    of Tests/SwanOAuthTests/Fixtures/pinned-typescript-oauth-scopes.json is not an \
    oracle — every outcome in it is `false`. Cause: \
    Scripts/upstream-scope-goldens/generate.mjs built the permissions value as \
    `new ScopePermissions(new ScopesSet(scopeString))`. Upstream's `ScopesSet` \
    `extends Set<string>` (packages/oauth/oauth-scopes/src/scopes-set.ts), so a \
    whole space-delimited STRING passed to it is iterated CHARACTER BY CHARACTER; \
    the resulting set holds single characters, none of which parse, and every \
    `allows*` therefore returns false. `ScopePermissions`'s own constructor is the \
    one that splits on SPACE (scope-permissions.ts:32-39), so the correct call is \
    `new ScopePermissions(scopeString)`. generate.mjs is fixed in this change; the \
    FIXTURE still carries the defective bytes and must be regenerated against a \
    full bddc99fb checkout before this suite can assert conformance.
    """
