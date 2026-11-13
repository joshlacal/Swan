import Foundation
import SwanCore
import SwanStorage
import XCTest
@testable import SwanOAuth

/// §5.7.5 — the wiring vectors. Two halves:
///
/// * the `LexiconManager` behaviours §5.7.6 names for porting
///   (`oauth-provider/lexicon/lexicon-manager.test.ts`), driven through
///   ``OAuthLexiconScopeResolution`` rather than through a live resolver, because
///   what is under test here is the *transformation*, not the proof chain — P2-G
///   owns the proof vectors and duplicating them would test the stub;
/// * the properties only this lane can assert: the deliberate error-code
///   asymmetry, the (a) → (b) → (c) ordering, and that resolution is reachable
///   from exactly two call sites.
final class OAuthLexiconScopeResolutionTests: XCTestCase {
    // MARK: - Fixtures

    private static let owner = "did:plc:ownerownerownerownerowner"
    private static let user = "did:plc:useruseruseruseruseruser"
    private static let forum = "com.example.forum.space"
    private static let thread = "com.example.forum.thread"
    private static let reply = "com.example.forum.reply"
    private static let authority = "com.example.forum.auth"

    /// A resolver that answers from a fixed table and COUNTS its calls.
    ///
    /// The count is not decoration: three vectors here assert a *number of
    /// resolutions*, and one of them (`type=*`) asserts **zero**. A stub that
    /// only answered questions could not fail those.
    private final class StubLexiconResolver: SwanLexiconResolving, @unchecked Sendable {
        private let documents: [String: SwanLexiconDocument]
        private let lock = NSLock()
        private var _resolved: [String] = []

        init(_ documents: [String: SwanLexiconDocument]) { self.documents = documents }

        var resolved: [String] { lock.withLock { _resolved } }
        var resolutionCount: Int { lock.withLock { _resolved.count } }

        func resolve(_ nsid: String) async throws -> SwanLexiconResolution {
            lock.withLock { _resolved.append(nsid) }
            guard let document = documents[nsid] else { return .unresolvable }
            return .resolved(
                document,
                sourceURI: "at://\(Self.stubDID)/com.atproto.lexicon.schema/\(nsid)",
                verifiedCID: "bafyreistubstubstubstubstubstubstubstubstubstubstubstubstub"
            )
        }

        private static let stubDID = "did:plc:authorityauthorityauthority"
    }

    private static func space(_ collections: [String]) -> SwanLexiconDocument {
        .space(LexiconSpace(title: "Forum", collections: collections))
    }

    private static func permissionSet(
        _ permissions: [LexiconPermission]
    ) -> SwanLexiconDocument {
        .permissionSet(LexiconPermissionSet(permissions: permissions))
    }

    // MARK: - (b) expandSpaceCollections — the ported LexiconManager vectors

    func testSpaceDeclarationAllowsLongTitlesAndCrossNamespaceCollections() throws {
        let title = String(repeating: "Forum", count: 20)
        let bytes = try JSONSerialization.data(withJSONObject: [
            "type": "space", "title": title,
            "collections": [Self.thread, "org.other.reply"],
        ])
        let space = try JSONDecoder().decode(LexiconSpace.self, from: bytes)
        XCTAssertEqual(space.title, title)
        XCTAssertEqual(space.collections, [Self.thread, "org.other.reply"])
    }

    func testSpaceDeclarationRejectsWildcardAndMalformedCollections() throws {
        for collection in ["*", "com.example.*", "invalid"] {
            let bytes = try JSONSerialization.data(withJSONObject: [
                "type": "space", "title": "Forum", "collections": [collection],
            ])
            XCTAssertThrowsError(try JSONDecoder().decode(LexiconSpace.self, from: bytes))
        }
    }

    func testInvalidDeclaredDefaultsCannotBecomeWildcardWriteGrants() async throws {
        let resolver = StubLexiconResolver([Self.forum: Self.space(["*"])])
        do {
            _ = try await OAuthLexiconScopeResolution.expandSpaceCollections(
                ["space:\(Self.forum)"], resolver: resolver, stage: .tokenMint
            )
            XCTFail("a declaration cannot supply a wildcard write default")
        } catch let error as OAuthScopeResolutionError {
            XCTAssertEqual(error.failure, .spaceTypeInvalidCollections(nsid: Self.forum))
        }
    }

    /// `'materializes the declared collections into a bare grant'`.
    func testMaterialisesDeclaredCollectionsIntoABareGrant() async throws {
        let resolver = StubLexiconResolver([Self.forum: Self.space([Self.thread, Self.reply])])
        let result = try await OAuthLexiconScopeResolution.expandSpaceCollections(
            ["space:\(Self.forum)?authority=\(Self.owner)"],
            resolver: resolver,
            stage: .tokenMint
        )
        XCTAssertEqual(
            result.scopes,
            ["space:\(Self.forum)?authority=\(Self.owner)&collection=\(Self.reply)&collection=\(Self.thread)"]
        )
    }

    /// `'leaves a grant that already names collections alone'` and
    /// `'leaves a collection=* grant alone'`. Both must also perform **no**
    /// resolution: `hasCollections` is checked before the NSID is collected
    /// (`lexicon-manager.ts:78-81`), so a qualified grant costs no network.
    func testLeavesGrantsThatAlreadyNameCollectionsAloneWithoutResolving() async throws {
        let resolver = StubLexiconResolver([Self.forum: Self.space([Self.thread])])
        let qualified: Set<String> = [
            "space:\(Self.forum)?authority=\(Self.owner)&collection=\(Self.reply)",
            "space:\(Self.forum)?authority=\(Self.owner)&collection=*",
        ]
        let result = try await OAuthLexiconScopeResolution.expandSpaceCollections(
            qualified, resolver: resolver, stage: .tokenMint
        )
        XCTAssertEqual(result.scopes, qualified)
        XCTAssertEqual(resolver.resolutionCount, 0)
    }

    /// `'does not resolve a wildcard space type'` (`:80`, `:90`). `space:*` names
    /// no one type, so there is no declaration to expand from — and, again, no
    /// resolution to perform.
    func testWildcardSpaceTypeIsSkippedAndResolvesNothing() async throws {
        let resolver = StubLexiconResolver([:])
        let scopes: Set<String> = ["space:*?authority=\(Self.owner)"]
        let result = try await OAuthLexiconScopeResolution.expandSpaceCollections(
            scopes, resolver: resolver, stage: .tokenMint
        )
        XCTAssertEqual(result.scopes, scopes)
        XCTAssertEqual(resolver.resolutionCount, 0)
    }

    /// `'throws when a space type cannot be resolved'` (`lexicon-manager.ts:68-73`).
    ///
    /// **The direction is the point.** Passing the bare grant through would let
    /// an unreachable or hostile authority silently widen what it covers, and
    /// would mint a token narrower than the user consented to. This test fails if
    /// anyone "helpfully" makes an unresolvable declaration a pass-through.
    func testThrowsWhenASpaceTypeCannotBeResolved() async throws {
        let resolver = StubLexiconResolver([:])
        await XCTAssertThrowsErrorAsync(
            try await OAuthLexiconScopeResolution.expandSpaceCollections(
                ["space:\(Self.forum)?authority=\(Self.owner)"],
                resolver: resolver,
                stage: .tokenMint
            )
        ) { error in
            guard let resolution = error as? OAuthScopeResolutionError else {
                return XCTFail("expected OAuthScopeResolutionError, got \(error)")
            }
            XCTAssertEqual(resolution.failure, .spaceTypeUnresolvable(nsid: Self.forum))
        }
    }

    /// `'throws when the resolved document is not a space'`
    /// (`lexicon-manager.ts:156-159`). A proved document of the wrong kind is a
    /// hard failure, not a pass-through — same reasoning as above.
    func testThrowsWhenTheResolvedDocumentIsNotASpace() async throws {
        let resolver = StubLexiconResolver([Self.forum: .other])
        await XCTAssertThrowsErrorAsync(
            try await OAuthLexiconScopeResolution.expandSpaceCollections(
                ["space:\(Self.forum)?authority=\(Self.owner)"],
                resolver: resolver,
                stage: .tokenMint
            )
        ) { error in
            XCTAssertEqual(
                (error as? OAuthScopeResolutionError)?.failure,
                .spaceTypeNotASpace(nsid: Self.forum)
            )
        }
    }

    /// `'leaves a bare grant alone when the space declares no collections'`
    /// (`lexicon-manager.test.ts:178-187`). Resolvable, with nothing to expand
    /// to: a read-only space type is a legitimate declaration, so an empty list
    /// is **not** an error — and must not be confused with "unresolvable", which
    /// is the case immediately above.
    func testEmptyDeclaredCollectionListIsNotAnError() async throws {
        let resolver = StubLexiconResolver([Self.forum: Self.space([])])
        let scopes: Set<String> = ["space:\(Self.forum)?authority=\(Self.owner)"]
        let result = try await OAuthLexiconScopeResolution.expandSpaceCollections(
            scopes, resolver: resolver, stage: .tokenMint
        )
        XCTAssertEqual(result.scopes, scopes)
        XCTAssertEqual(resolver.resolutionCount, 1, "the type WAS resolved; it declared nothing")
    }

    /// `'passes non-space scopes through untouched'` and
    /// `'expands a space grant alongside unrelated scopes'`.
    func testPassesNonSpaceScopesThroughUntouched() async throws {
        let resolver = StubLexiconResolver([Self.forum: Self.space([Self.thread])])
        let result = try await OAuthLexiconScopeResolution.expandSpaceCollections(
            ["atproto", "repo:app.bsky.feed.post", "space:\(Self.forum)?authority=\(Self.owner)"],
            resolver: resolver,
            stage: .tokenMint
        )
        XCTAssertTrue(result.scopes.contains("atproto"))
        XCTAssertTrue(result.scopes.contains("repo:app.bsky.feed.post"))
        XCTAssertTrue(
            result.scopes.contains(
                "space:\(Self.forum)?authority=\(Self.owner)&collection=\(Self.thread)"
            )
        )
    }

    /// `'expands several space grants independently'` — two types, two
    /// declarations, one resolution each.
    func testExpandsSeveralSpaceGrantsIndependently() async throws {
        let other = "com.example.wiki.space"
        let resolver = StubLexiconResolver([
            Self.forum: Self.space([Self.thread]),
            other: Self.space(["com.example.wiki.page"]),
        ])
        let result = try await OAuthLexiconScopeResolution.expandSpaceCollections(
            [
                "space:\(Self.forum)?authority=\(Self.owner)",
                "space:\(other)?authority=\(Self.owner)",
            ],
            resolver: resolver,
            stage: .tokenMint
        )
        XCTAssertEqual(
            result.scopes,
            [
                "space:\(Self.forum)?authority=\(Self.owner)&collection=\(Self.thread)",
                "space:\(other)?authority=\(Self.owner)&collection=com.example.wiki.page",
            ]
        )
        XCTAssertEqual(Set(resolver.resolved), [Self.forum, other])
    }

    /// **(b) is NOT include-specific**, which is the whole reason filing it under
    /// "Phase 2" left Phase 1 with a silent grant-narrowing rather than merely an
    /// unimplemented feature.
    ///
    /// The scope set here contains no `include:` at all — it is bulleted.app's
    /// shape — and it is still rewritten. An implementation that only ran
    /// expansion over include-derived grants passes every other test in this
    /// file and fails this one.
    func testExpansionReachesSpaceGrantsThatNoIncludeProduced() async throws {
        let resolver = StubLexiconResolver([Self.forum: Self.space([Self.thread])])
        let result = try await OAuthLexiconScopeResolution.expandSpaceCollections(
            ["atproto", "space:\(Self.forum)?authority=\(Self.owner)"],
            resolver: resolver,
            stage: .tokenMint
        )
        XCTAssertEqual(resolver.resolved, [Self.forum])
        XCTAssertTrue(
            result.scopes.contains(
                "space:\(Self.forum)?authority=\(Self.owner)&collection=\(Self.thread)"
            )
        )
    }

    /// The **settled** verb outcome (`315e4b7e`): `withDefaultCollections` passes
    /// `action` through unchanged, so a bare `space:<type>` grant IS writable
    /// after materialisation. That is the intended result of this lane, and it is
    /// asserted rather than left implicit so that re-adding the reverted
    /// write-verb guard fails here loudly instead of silently narrowing every
    /// grant Swan issues.
    func testABareGrantIsWritableAfterMaterialisation() async throws {
        let resolver = StubLexiconResolver([Self.forum: Self.space([Self.thread])])
        let result = try await OAuthLexiconScopeResolution.expandSpaceCollections(
            ["space:\(Self.forum)?authority=\(Self.owner)"],
            resolver: resolver,
            stage: .tokenMint
        )
        let permissions = SwanScopePermissions(rawScopes: result.scopes, subject: Self.owner)
        XCTAssertTrue(
            permissions.allowsSpace(
                SpaceScopeTarget(
                    type: Self.forum,
                    authority: Self.owner,
                    skey: "own",
                    operation: .write(.create, collection: Self.thread)
                )
            ),
            """
            §5.7.5(b): materialisation arms the schema-default action list. A \
            guard dropping write verbs when `action` was unstated was tried and \
            REVERTED — it made create/update/delete unreachable for every grant \
            that ever existed. Read `withDefaultCollections`'s doc comment before \
            changing this.
            """
        )
    }

    /// The second, separately-bounded population (§5.7.4): distinct space-type
    /// NSIDs cap at 8, not at the `include:` cap of 4.
    func testSpaceTypePopulationHasItsOwnCap() async throws {
        let resolver = StubLexiconResolver([:])
        let scopes = Set((0 ..< 9).map { "space:com.example.t\($0).space?authority=\(Self.owner)" })
        await XCTAssertThrowsErrorAsync(
            try await OAuthLexiconScopeResolution.expandSpaceCollections(
                scopes, resolver: resolver, stage: .tokenMint
            )
        ) { error in
            XCTAssertEqual(
                (error as? OAuthScopeResolutionError)?.failure,
                .budget(.tooManyDistinctNSIDs(.spaceTypes, requested: 9))
            )
            XCTAssertEqual(resolver.resolutionCount, 0, "the cap precedes the work it bounds")
        }
    }

    // MARK: - (a) include: → concrete

    func testIncludeExpandsToConcreteGrantsAndDoesNotSurvive() async throws {
        let resolver = StubLexiconResolver([
            Self.authority: Self.permissionSet([
                LexiconPermission(
                    resource: "repo",
                    fields: ["collection": .list([.string(Self.thread)])]
                ),
            ]),
        ])
        let result = try await OAuthLexiconScopeResolution.expandIncludes(
            ["atproto", "include:\(Self.authority)"],
            resolver: resolver,
            stage: .pushedAuthorizationRequest
        )
        XCTAssertFalse(
            result.scopes.contains("include:\(Self.authority)"),
            "lexicon-manager.ts:52-56 replaces the include; it does not keep it beside its expansion"
        )
        XCTAssertTrue(result.scopes.contains("repo:\(Self.thread)"))
        XCTAssertTrue(result.scopes.contains("atproto"))
        XCTAssertTrue(result.emptyExpansions.isEmpty)
    }

    /// An `include:` that resolves and expands to **nothing** is not an error
    /// (§5.7.5's last row). It is reported, because a `.warn` reaches an operator
    /// and the person authorizing never sees it.
    func testEmptyExpansionIsNotAnErrorAndIsReported() async throws {
        // Every entry drops: `blob` is not one of the three families expansion
        // admits (gate 1), and the repo entry names a collection outside the
        // include's namespace (gate 3).
        let resolver = StubLexiconResolver([
            Self.authority: Self.permissionSet([
                LexiconPermission(resource: "blob", fields: ["accept": .list([.string("image/*")])]),
                LexiconPermission(
                    resource: "repo",
                    fields: ["collection": .list([.string("app.bsky.feed.post")])]
                ),
            ]),
        ])
        let result = try await OAuthLexiconScopeResolution.expandIncludes(
            ["atproto", "include:\(Self.authority)"],
            resolver: resolver,
            stage: .pushedAuthorizationRequest
        )
        XCTAssertEqual(result.scopes, ["atproto"])
        XCTAssertEqual(result.emptyExpansions, [Self.authority])
    }

    func testIncludeResolvingToANonPermissionSetIsRefused() async throws {
        let resolver = StubLexiconResolver([Self.authority: Self.space([Self.thread])])
        await XCTAssertThrowsErrorAsync(
            try await OAuthLexiconScopeResolution.expandIncludes(
                ["include:\(Self.authority)"],
                resolver: resolver,
                stage: .pushedAuthorizationRequest
            )
        ) { error in
            XCTAssertEqual(
                (error as? OAuthScopeResolutionError)?.failure,
                .includeNotAPermissionSet(nsid: Self.authority)
            )
        }
    }

    /// Expansion must not INVENT provenance (§9-D23). An include-derived grant's
    /// author is the permission-set document, so `wasStated` reports what the
    /// document wrote — not everything, which would flip the delegation fence
    /// open on a grant nobody spelled that way.
    func testExpansionCarriesTheDocumentsProvenanceNotAFabricatedOne() async throws {
        let resolver = StubLexiconResolver([
            Self.authority: Self.permissionSet([
                LexiconPermission(
                    resource: "space",
                    fields: ["spaceType": .string(Self.forum)]
                ),
            ]),
        ])
        let result = try await OAuthLexiconScopeResolution.expandIncludes(
            ["include:\(Self.authority)"],
            resolver: resolver,
            stage: .pushedAuthorizationRequest
        )
        let expanded = try XCTUnwrap(result.scopes.first { $0.hasPrefix("space:") })
        let stated = result.provenance.statedParameterKeys[expanded]
        XCTAssertEqual(
            stated, ["type"],
            """
            §9-D23: the document wrote only the space type. `authority`, `skey`, \
            `action` and `manage` were defaulted and must not read as stated.
            """
        )
    }

    // MARK: - The deliberate error-code asymmetry

    /// §5.7.5: the SAME root cause is `invalid_scope` at PAR and
    /// `invalid_request` at token mint (`request-manager.ts:293-312` vs
    /// `token-manager.ts:135-138`). Upstream's asymmetry, kept for interop.
    ///
    /// One test, both legs, one input — so nobody can "tidy" one side without the
    /// other side failing.
    func testSameRootCauseReportsDifferentCodesOnTheTwoLegs() async throws {
        let resolver = StubLexiconResolver([:])
        var codes: [OAuthScopeResolutionStage: String] = [:]
        for stage in [OAuthScopeResolutionStage.pushedAuthorizationRequest, .tokenMint] {
            do {
                _ = try await OAuthLexiconScopeResolution.expandIncludes(
                    ["include:\(Self.authority)"], resolver: resolver, stage: stage
                )
                XCTFail("an unresolvable include must not pass")
            } catch let error as OAuthScopeResolutionError {
                XCTAssertEqual(error.failure, .includeUnresolvable(nsid: Self.authority))
                codes[stage] = error.oauthErrorCode
            }
        }
        XCTAssertEqual(codes[.pushedAuthorizationRequest], "invalid_scope")
        XCTAssertEqual(codes[.tokenMint], "invalid_request")
    }

    // MARK: - Call site 2 — all three transformations, in order

    /// (a) → (b) → (c). The vector is an `include:` that expands to a **bare**
    /// `space:` grant with a defaulted `authority`, so it can only come out right
    /// if all three ran and ran in this order:
    ///
    /// * (a) must precede (b), or the space grant does not exist yet to
    ///   materialise;
    /// * (b) must precede (c) — running (c) first rewrites the scope string and
    ///   leaves (b) matching a stale provenance key for no benefit;
    /// * (c) must run at all, or `authority=self` matches nothing.
    func testTokenMintRunsAllThreeTransformationsInOrder() async throws {
        let resolver = StubLexiconResolver([
            Self.authority: Self.permissionSet([
                LexiconPermission(resource: "space", fields: ["spaceType": .string(Self.forum)]),
            ]),
            Self.forum: Self.space([Self.thread]),
        ])
        let binding = OAuthClientBinding(
            issuer: "https://swan.example",
            clientID: "https://client.example/metadata.json",
            redirectURI: "https://client.example/callback",
            scopes: ["atproto", "include:\(Self.authority)"]
        )
        let resolved = try await OAuthLexiconScopeResolution.resolvingLexiconGrants(
            binding, subject: Self.user, resolver: resolver
        )
        XCTAssertEqual(
            resolved.scopes,
            [
                "atproto",
                "space:\(Self.forum)?authority=\(Self.user)&collection=\(Self.thread)",
            ]
        )
        XCTAssertEqual(
            resolved.requestedScopes, ["atproto", "include:\(Self.authority)"],
            "§6.7: the client's own bytes survive on `scopesRequested`"
        )
    }

    /// No resolver configured is Phase-1 behaviour, stated rather than
    /// accidental: `include:` persists and grants nothing, and a bare
    /// `space:<type>` materialises no write targets. Both are divergences from a
    /// conformant AS; both close when `--enable-lexicon-resolution` is set.
    func testWithoutAResolverBothTransformationsArePhase1PassThroughs() async throws {
        let binding = OAuthClientBinding(
            issuer: "https://swan.example",
            clientID: "https://client.example/metadata.json",
            redirectURI: "https://client.example/callback",
            scopes: ["atproto", "include:\(Self.authority)", "space:\(Self.forum)"]
        )
        let resolved = try await OAuthLexiconScopeResolution.resolvingLexiconGrants(
            binding, subject: Self.user, resolver: nil
        )
        XCTAssertTrue(resolved.scopes.contains("include:\(Self.authority)"))
        XCTAssertTrue(resolved.scopes.contains("space:\(Self.forum)?authority=\(Self.user)"))
        XCTAssertFalse(
            SwanScopePermissions(rawScopes: resolved.scopes, subject: Self.user).allowsSpace(
                SpaceScopeTarget(
                    type: Self.forum,
                    authority: Self.user,
                    skey: "own",
                    operation: .write(.create, collection: Self.thread)
                )
            ),
            "Phase-1 DIVERGENCE (§7.4 Stage 6 check 3): no materialisation, no write targets"
        )
    }

    // MARK: - Call site 3 — request time: NEVER

    /// §5.7.5 item 3, asserted rather than asserted-in-prose.
    ///
    /// A resource request reaches the matcher through `SwanScopePermissions`,
    /// which takes stored strings and a subject and nothing else. The counting
    /// resolver proves the negative: it advances during mint and then does not
    /// advance across every match a resource request can make. A doc comment
    /// cannot notice the day someone adds an `await resolver.resolve(…)` behind
    /// `allowsSpace`; this can.
    func testResourcePlaneAuthorizationPerformsNoLexiconResolution() async throws {
        let resolver = StubLexiconResolver([
            Self.authority: Self.permissionSet([
                LexiconPermission(resource: "space", fields: ["spaceType": .string(Self.forum)]),
            ]),
            Self.forum: Self.space([Self.thread]),
        ])
        let binding = OAuthClientBinding(
            issuer: "https://swan.example",
            clientID: "https://client.example/metadata.json",
            redirectURI: "https://client.example/callback",
            scopes: ["atproto", "include:\(Self.authority)"]
        )
        let minted = try await OAuthLexiconScopeResolution.resolvingLexiconGrants(
            binding, subject: Self.user, resolver: resolver
        )
        let afterMint = resolver.resolutionCount
        XCTAssertGreaterThan(afterMint, 0, "positive control: mint DOES resolve")

        // Everything a route can ask of a validated grant.
        let permissions = SwanScopePermissions(rawScopes: minted.scopes, subject: Self.user)
        _ = permissions.hasBaseATProtocolScope
        _ = permissions.hasResourceScope
        _ = permissions.allowsRepo(.init(collection: Self.thread, action: .create))
        _ = permissions.allowsBlob(.init(mime: "image/png"))
        _ = permissions.allowsIdentity(.init(attr: .handle))
        _ = permissions.allowsAccount(.init(attr: .email, action: .read))
        _ = permissions.allowsSpace(
            SpaceScopeTarget(
                type: Self.forum,
                authority: Self.user,
                skey: "own",
                operation: .write(.create, collection: Self.thread)
            )
        )
        XCTAssertEqual(
            resolver.resolutionCount, afterMint,
            """
            §5.7.5 item 3: a resource request performs ZERO outbound I/O for \
            authorization. Stored scopes are already expanded, self-resolved and \
            collection-materialised by the time a bearer token reaches a route.
            """
        )
    }

    // MARK: - Honest deadline racing

    func testNeverReturningOperationDoesNotHoldSwanLexiconDeadlinePastDeadline() async throws {
        struct TestExpiry: Error, Equatable {}
        let clock = ContinuousClock()
        let startedAt = clock.now

        do {
            _ = try await SwanLexiconDeadline.run(seconds: 0.05, onExpiry: TestExpiry()) {
                try await withUnsafeThrowingContinuation { (_: UnsafeContinuation<Int, any Error>) in
                    // Deliberately never resumes continuation and ignores cancellation,
                    // simulating an uncooperative stalled blocking operation.
                }
            }
            XCTFail("expected deadline expiry")
        } catch is TestExpiry {
            let elapsed = startedAt.duration(to: clock.now)
            XCTAssertLessThan(
                elapsed,
                .milliseconds(250),
                "SwanLexiconDeadline.run must return at deadline without awaiting uncooperative children"
            )
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testCancellationCooperativeOperationYieldsSpecifiedExpiryOnDeadlineRace() async throws {
        struct TestExpiry: Error, Equatable {}
        for _ in 0 ..< 20 {
            do {
                _ = try await SwanLexiconDeadline.run(seconds: 0.005, onExpiry: TestExpiry()) {
                    // Cooperative operation: sleeps and throws CancellationError if cancelled
                    try await Task.sleep(for: .seconds(5))
                    return 42
                }
                XCTFail("expected deadline expiry")
            } catch is TestExpiry {
                // Expected: onExpiry error must be preserved
            } catch is CancellationError {
                XCTFail("race condition: cancellation laundered into CancellationError instead of specified expiry")
            } catch {
                XCTFail("unexpected error: \(error)")
            }
        }
    }

    func testCallerCancellationYieldsCancellationErrorRatherThanExpiry() async throws {
        struct TestExpiry: Error, Equatable {}
        let task = Task {
            try await SwanLexiconDeadline.run(seconds: 5.0, onExpiry: TestExpiry()) {
                try await Task.sleep(for: .seconds(10))
                return 42
            }
        }
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("expected cancellation")
        } catch is CancellationError {
            // Expected
        } catch is TestExpiry {
            XCTFail("caller cancellation must yield CancellationError, not onExpiry")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }
}

// MARK: - Async throwing assertion

/// XCTest has no async `XCTAssertThrowsError`. Local rather than shared: it is
/// four lines, and a test-support target would be a new link edge.
private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ handler: (any Error) -> Void
) async {
    do {
        _ = try await expression()
        XCTFail("expected an error", file: file, line: line)
    } catch {
        handler(error)
    }
}
