import Foundation
import XCTest
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite
@testable import SwanSpaces
import SwanStorage

/// **§5.7.5's second call site is "token mint / **refresh**", and refresh was
/// the half that never re-derived** (plan finding F2).
///
/// Upstream rebuilds the token scope on every rotation —
/// `buildTokenScope(parameters.scope!, account.did)` at `token-manager.ts:260`,
/// from the raw requested scope, immediately before `store.rotateToken` writes
/// it. Swan froze the grant at mint: `redeemRefreshForClient` returned
/// `family.binding.scopes` and the rotation transaction took token digests and
/// nothing else.
///
/// **Why that is more than an unwired feature.** §5.7.4 added a 24-hour hard
/// cache expiry as a deliberate Swan divergence, and its stated rationale argues
/// *from* re-derivation: without the expiry, "a permission set that was
/// **narrowed** upstream would keep minting the wider grant indefinitely
/// whenever the resolver is unreachable". With no re-derivation at all that
/// safeguard was inert — a 14-day refresh family kept its mint-time grant for
/// its entire life, resolver reachable or not.
///
/// So the property under test is not "refresh calls the resolver". It is
/// **narrowing takes effect**: a permission set that shrinks between mint and
/// refresh must yield a narrower token, observed at the resource plane rather
/// than at the store call.
final class RefreshScopeRederivationTests: XCTestCase, @unchecked Sendable {
    private static let spaceType = "app.example.forum"
    private static let thread = "app.example.forum.thread"
    private static let reply = "app.example.forum.reply"

    /// `.localhostBridge` throughout, for the same reason the §9-D20 suite gives:
    /// `redeemLocalhostPublicRefresh` is a refresh path a test can drive without
    /// standing up remote client-metadata retrieval, and it rotates through the
    /// same durable transaction as `redeemRefreshForClient`.

    // MARK: - The property: narrowing takes effect

    /// Mint against a space type declaring two collections; narrow the
    /// authority's declaration to one; refresh; assert the refreshed token can
    /// no longer write the dropped collection and can still write the kept one.
    ///
    /// **Negative control.** With the re-derivation removed — pass
    /// `rewrittenGrant: nil` at `DurableOAuthTokenService.swift`'s rotation call,
    /// or return `nil` unconditionally from `rederivedGrant(for:)` — the dropped
    /// collection stays writable and the first assertion fails. The kept-collection
    /// assertion passes either way, which is exactly why it cannot stand alone:
    /// it is a positive control, not the property.
    func testNarrowingAPermissionSetTakesEffectOnRefresh() async throws {
        let resolver = MutableStubLexiconResolver([
            Self.spaceType: .space(LexiconSpace(name: "Forum", collections: [Self.thread, Self.reply])),
        ])
        // A BARE space grant: no `collection`, so what it covers is whatever the
        // authority declares. That is the shape §5.7.5(b) materialises, and the
        // only shape a narrowing at the authority can move.
        let client = try PermissionedScopeClient(
            scopes: ["atproto", "space:\(Self.spaceType)"], kind: .localhostBridge
        )
        let fixture = try await PermissionedScopeFixture.make(lexiconResolver: resolver)
        defer { Task { await fixture.tearDown() } }

        let issued = try await fixture.mint(client: client, proofID: "rederive-narrow-mint")
        // Precondition: mint materialised BOTH collections. Without this the test
        // could pass by never having granted the dropped collection at all.
        let minted = try await fixture.permissions(
            accessToken: issued.accessToken, client: client, jti: "rederive-narrow-before"
        )
        XCTAssertTrue(
            minted.allowsSpace(Self.write(Self.reply)),
            """
            precondition failed: mint did not materialise `\(Self.reply)` into the \
            bare grant, so a later narrowing cannot be observed (§5.7.5(b))
            """
        )

        // The authority narrows its declaration. Nothing about the client, its
        // registration or its requested bytes changes.
        resolver.replace([
            Self.spaceType: .space(LexiconSpace(name: "Forum", collections: [Self.thread])),
        ])

        let refreshToken = try XCTUnwrap(issued.refreshToken)
        let session = try client.session(proofID: "rederive-narrow-refresh")
        let rotated = try await fixture.runtime.tokenService.redeemLocalhostPublicRefresh(
            refreshToken,
            clientID: client.clientID,
            dpopProof: session.dpopProof,
            requestedScopes: client.scopeSet
        )

        // Read the grant back through a REOPENED database: the assertion has to
        // be about what the rotation persisted, not about a value still live in
        // the process that computed it.
        let reloaded = try await fixture.reopeningStorage()
        defer { Task { await reloaded.tearDown() } }
        let refreshed = try await reloaded.permissions(
            accessToken: rotated.accessToken, client: client, jti: "rederive-narrow-after"
        )
        XCTAssertFalse(
            refreshed.allowsSpace(Self.write(Self.reply)),
            """
            NARROWING DOES NOT TAKE EFFECT (plan F2). The authority dropped \
            `\(Self.reply)` from `\(Self.spaceType)`'s declaration, the client \
            refreshed, and the rotated token still writes it. Refresh must \
            re-derive the token scope from the REQUESTED baseline \
            (`scopes_requested ?? scopes`, §9-D20) and persist the result in the \
            rotation transaction — see `DurableOAuthTokenService.rederivedGrant`.
            """
        )
        XCTAssertTrue(
            refreshed.allowsSpace(Self.write(Self.thread)),
            """
            over-correction: re-derivation narrowed the grant past what the \
            authority declares. `\(Self.thread)` is still declared and must \
            still be writable.
            """
        )
    }

    /// The requested baseline is not consumed by the rotation that reads it: a
    /// second refresh re-derives from the same client bytes, so a narrowing can
    /// be *reverted* by the authority as well as applied.
    ///
    /// This is the load-bearing half of "rotation must not rewrite the requested
    /// side". If the rotation had written the narrowed grant back over
    /// `scopes_requested`, the widening below would be unreachable — the second
    /// re-derivation would start from the already-narrowed set — and the
    /// §9-D20 comparison would begin refusing the client's own original bytes.
    func testTheRequestedBaselineSurvivesRotationSoAWideningAlsoTakesEffect() async throws {
        let resolver = MutableStubLexiconResolver([
            Self.spaceType: .space(LexiconSpace(name: "Forum", collections: [Self.thread])),
        ])
        let client = try PermissionedScopeClient(
            scopes: ["atproto", "space:\(Self.spaceType)"], kind: .localhostBridge
        )
        let fixture = try await PermissionedScopeFixture.make(lexiconResolver: resolver)
        defer { Task { await fixture.tearDown() } }

        let issued = try await fixture.mint(client: client, proofID: "rederive-widen-mint")
        var refreshToken = try XCTUnwrap(issued.refreshToken)

        resolver.replace([
            Self.spaceType: .space(LexiconSpace(name: "Forum", collections: [Self.thread, Self.reply])),
        ])
        let rotated = try await fixture.runtime.tokenService.redeemLocalhostPublicRefresh(
            refreshToken,
            clientID: client.clientID,
            // The client re-presents its ORIGINAL requested bytes, exactly as
            // §9-D20 requires; a rotation that had rewritten the baseline would
            // refuse them here.
            dpopProof: try client.session(proofID: "rederive-widen-r1").dpopProof,
            requestedScopes: client.scopeSet
        )
        refreshToken = try XCTUnwrap(rotated.refreshToken)

        let after = try await fixture.permissions(
            accessToken: rotated.accessToken, client: client, jti: "rederive-widen-after"
        )
        XCTAssertTrue(
            after.allowsSpace(Self.write(Self.reply)),
            "the authority re-declared `\(Self.reply)`; the refreshed grant must carry it"
        )

        // And once more, to prove the baseline is stable across generations
        // rather than merely surviving one rotation.
        _ = try await fixture.runtime.tokenService.redeemLocalhostPublicRefresh(
            refreshToken,
            clientID: client.clientID,
            dpopProof: try client.session(proofID: "rederive-widen-r2").dpopProof,
            requestedScopes: client.scopeSet
        )
    }

    /// Explicit collections opt out of live defaults. Updating a declaration
    /// changes neither the client's stated collection set nor its read access.
    func testExplicitCollectionsRemainStableWhenTheDeclarationChanges() async throws {
        let resolver = MutableStubLexiconResolver([
            Self.spaceType: .space(LexiconSpace(name: "Forum", collections: [Self.thread])),
        ])
        let client = try PermissionedScopeClient(
            scopes: ["atproto", "space:\(Self.spaceType)?collection=\(Self.thread)"],
            kind: .localhostBridge
        )
        let fixture = try await PermissionedScopeFixture.make(lexiconResolver: resolver)
        defer { Task { await fixture.tearDown() } }
        let issued = try await fixture.mint(client: client, proofID: "rederive-explicit-mint")

        resolver.replace([
            Self.spaceType: .space(LexiconSpace(name: "Forum", collections: [Self.reply])),
        ])
        let rotated = try await fixture.runtime.tokenService.redeemLocalhostPublicRefresh(
            try XCTUnwrap(issued.refreshToken),
            clientID: client.clientID,
            dpopProof: try client.session(proofID: "rederive-explicit-refresh").dpopProof,
            requestedScopes: client.scopeSet
        )
        let refreshed = try await fixture.permissions(
            accessToken: rotated.accessToken, client: client, jti: "rederive-explicit-after"
        )
        XCTAssertTrue(refreshed.allowsSpace(Self.write(Self.thread)))
        XCTAssertFalse(refreshed.allowsSpace(Self.write(Self.reply)))
        XCTAssertTrue(refreshed.allowsSpace(SpaceScopeTarget(
            type: Self.spaceType,
            authority: PermissionedScopeFixture.subject,
            skey: "self",
            operation: .readSelf(aggregate: false, collection: Self.reply)
        )))
    }

    // MARK: - Failure policy

    /// **Chosen policy: a re-derivation failure FAILS the refresh, and does not
    /// consume the presented refresh token.**
    ///
    /// Serving a stale document on a fetch failure is the *cache's* job
    /// (§5.7.5's matrix, row 1), a different layer from this one — so by the time
    /// a failure reaches the rotation, the cache has already declined: it has
    /// nothing, or its 24 h hard expiry has passed. Continuing at that point
    /// would re-mint the wider grant precisely when Swan can no longer show it is
    /// still granted, which is the outcome §5.7.4's hard expiry exists to
    /// prevent. Upstream makes the same call in the same place and says so
    /// (`token-manager.ts:257-259`).
    ///
    /// The second assertion is the part that makes the policy safe rather than
    /// merely strict: re-derivation runs BEFORE the rotation transaction, so a
    /// transient authority outage costs the client one failed refresh, not its
    /// refresh token.
    func testAnUnresolvableAuthorityFailsTheRefreshWithoutConsumingTheToken() async throws {
        let resolver = MutableStubLexiconResolver([
            Self.spaceType: .space(LexiconSpace(name: "Forum", collections: [Self.thread])),
        ])
        let client = try PermissionedScopeClient(
            scopes: ["atproto", "space:\(Self.spaceType)"], kind: .localhostBridge
        )
        let fixture = try await PermissionedScopeFixture.make(lexiconResolver: resolver)
        defer { Task { await fixture.tearDown() } }

        let issued = try await fixture.mint(client: client, proofID: "rederive-fail-mint")
        let refreshToken = try XCTUnwrap(issued.refreshToken)

        resolver.replace([:])
        do {
            _ = try await fixture.runtime.tokenService.redeemLocalhostPublicRefresh(
                refreshToken,
                clientID: client.clientID,
                dpopProof: try client.session(proofID: "rederive-fail-r1").dpopProof,
                requestedScopes: client.scopeSet
            )
            XCTFail(
                """
                refresh succeeded while the space type could not be resolved. \
                Passing the bare grant through would let an unreachable or \
                hostile authority silently widen what it covers (§5.7.5(b)); \
                serving the stored grant is the cache's job and the cache has \
                already declined by this point.
                """
            )
        } catch {
            // Expected. The failure carries the token-leg code, not PAR's.
            XCTAssertEqual(
                (error as? OAuthScopeResolutionError)?.oauthErrorCode,
                "invalid_request",
                "§5.7.5's deliberate asymmetry: `invalid_request` on the token leg"
            )
        }

        // The refresh token was NOT burned: the authority recovers and the same
        // token still rotates.
        resolver.replace([
            Self.spaceType: .space(LexiconSpace(name: "Forum", collections: [Self.thread])),
        ])
        _ = try await fixture.runtime.tokenService.redeemLocalhostPublicRefresh(
            refreshToken,
            clientID: client.clientID,
            dpopProof: try client.session(proofID: "rederive-fail-r2").dpopProof,
            requestedScopes: client.scopeSet
        )
    }

    // MARK: - §9-D23: re-derivation must not invent or destroy provenance

    /// Refresh now REWRITES the family row, which is exactly the boundary
    /// §9-D23 is about. **Rewritten by Erratum 02 (§5.6.3 amendment):** the
    /// fence no longer consults `authority` statedness, only the stated
    /// `action` (plus a concrete type), so the same grant must EXCHANGE after
    /// a rotation just as it does after a mint. The assertion direction
    /// flipped, but the property is the same: re-derivation must carry the
    /// persisted provenance forward — if the stated-`action` bit were dropped
    /// during rotation, this would refuse, and that regression is exactly what
    /// this test now catches.
    func testRefreshDoesNotInventProvenanceForAResolvedAuthority() async throws {
        let requested = "space:\(Self.spaceType)?skey=*&action=read"
        let client = try PermissionedScopeClient(
            scopes: ["atproto", requested], kind: .localhostBridge
        )
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }

        let issued = try await fixture.mint(client: client, proofID: "rederive-prov-mint")
        XCTAssertTrue(
            issued.scopes.contains { $0.contains("authority=\(PermissionedScopeFixture.subject)") },
            "precondition: mint must have resolved `self`, or there is no invented statedness to test"
        )
        let refreshToken = try XCTUnwrap(issued.refreshToken)
        let rotated = try await fixture.runtime.tokenService.redeemLocalhostPublicRefresh(
            refreshToken,
            clientID: client.clientID,
            dpopProof: try client.session(proofID: "rederive-prov-refresh").dpopProof,
            requestedScopes: client.scopeSet
        )

        let reloaded = try await fixture.reopeningStorage()
        defer { Task { await reloaded.tearDown() } }
        let permissions = try await reloaded.permissions(
            accessToken: rotated.accessToken, client: client, jti: "rederive-prov-authorize"
        )
        XCTAssertTrue(
            permissions.allowsSpace(
                SpaceScopeTarget(
                    type: Self.spaceType,
                    authority: PermissionedScopeFixture.subject,
                    skey: "*",
                    operation: .delegationExchange
                )
            ),
            """
            PROVENANCE DROPPED THROUGH REFRESH (§9-D23, post-Erratum-02). The \
            client stated `action=read`; rotation re-derived the grant; if the \
            fence refuses, the stated-`action` bit was not carried forward from \
            `scope_provenance_requested`. The amendment made that bit the single \
            surviving delegation witness, so its survival across rotation is \
            load-bearing.
            """
        )
        XCTAssertTrue(
            permissions.allowsSpace(
                SpaceScopeTarget(
                    type: Self.spaceType,
                    authority: PermissionedScopeFixture.subject,
                    skey: "anything",
                    operation: .read(aggregate: false, collection: nil)
                )
            ),
            "positive control: the rotated grant still matches ordinary reads"
        )
    }

    /// The mirror direction, on the same path: a parameter the client DID write
    /// literally survives the rotation. Without this, "carry provenance forward"
    /// could be implemented as "carry nothing", which fails closed and silently
    /// disables the listing fence.
    func testRefreshPreservesProvenanceTheClientDidState() async throws {
        let requested =
            "space:\(Self.spaceType)?authority=\(PermissionedScopeFixture.subject)&skey=*&action=read"
        let client = try PermissionedScopeClient(
            scopes: ["atproto", requested], kind: .localhostBridge
        )
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }

        let issued = try await fixture.mint(client: client, proofID: "rederive-stated-mint")
        let refreshToken = try XCTUnwrap(issued.refreshToken)
        let rotated = try await fixture.runtime.tokenService.redeemLocalhostPublicRefresh(
            refreshToken,
            clientID: client.clientID,
            dpopProof: try client.session(proofID: "rederive-stated-refresh").dpopProof,
            requestedScopes: client.scopeSet
        )

        let reloaded = try await fixture.reopeningStorage()
        defer { Task { await reloaded.tearDown() } }
        let permissions = try await reloaded.permissions(
            accessToken: rotated.accessToken, client: client, jti: "rederive-stated-authorize"
        )
        XCTAssertTrue(
            permissions.allowsSpace(
                SpaceScopeTarget(
                    type: Self.spaceType,
                    authority: PermissionedScopeFixture.subject,
                    skey: "*",
                    operation: .delegationExchange
                )
            ),
            """
            W7 regression through refresh: every parameter here was literally \
            written by the client and survived mint; a rotation must not drop \
            those bits on the floor.
            """
        )
    }

    // MARK: - The two decisions that produce "leave it alone"

    /// **No churn.** An authority that keeps answering the same document must
    /// not rewrite the family row on every rotation. Neither outcome is visible
    /// from the rotation's outputs — a refresh that re-derived and agreed looks
    /// identical to one that skipped — so this asserts the decision directly.
    func testAnUnchangedDeclarationRewritesNothing() async throws {
        let resolver = MutableStubLexiconResolver([
            Self.spaceType: .space(LexiconSpace(name: "Forum", collections: [Self.thread])),
        ])
        let client = try PermissionedScopeClient(
            scopes: ["atproto", "space:\(Self.spaceType)"], kind: .localhostBridge
        )
        let fixture = try await PermissionedScopeFixture.make(lexiconResolver: resolver)
        defer { Task { await fixture.tearDown() } }

        let issued = try await fixture.mint(client: client, proofID: "rederive-nochurn-mint")
        let family = Self.family(mintedBy: issued)
        let unchanged = try await fixture.runtime.tokenService.rederivedGrant(for: family)
        XCTAssertNil(
            unchanged,
            "an unchanged declaration must produce no rewrite at all, not an identical one"
        )

        // Positive control on the same family: change the declaration and the
        // same call now produces a grant. Without this, `nil` above could mean
        // "re-derivation never runs".
        resolver.replace([
            Self.spaceType: .space(LexiconSpace(name: "Forum", collections: [Self.thread, Self.reply])),
        ])
        let changed = try await fixture.runtime.tokenService.rederivedGrant(for: family)
        XCTAssertNotNil(changed, "positive control: a changed declaration must produce a rewrite")
    }

    /// **No baseline, no rewrite.** A family written before
    /// `scope_provenance_requested` existed has requested bytes but no
    /// requested-side provenance. Re-deriving from an empty map would be a claim
    /// that the client stated nothing, which closes both §9-D23 fences on a live
    /// grant; the row is left frozen instead, bounded by the 14-day family
    /// lifetime.
    func testALegacyRowWithoutRequestedProvenanceIsLeftFrozen() throws {
        let requested = "space:\(Self.spaceType)?skey=*&action=read"
        let resolved =
            "space:\(Self.spaceType)?authority=\(PermissionedScopeFixture.subject)&skey=*&action=read"
        let legacy = OAuthClientBinding(
            issuer: PermissionedScopeFixture.issuer.absoluteString,
            clientID: "http://localhost",
            redirectURI: PermissionedScopeFixture.redirectURI.absoluteString,
            scopes: ["atproto", resolved],
            scopesRequested: ["atproto", requested],
            scopeProvenance: OAuthScopeProvenance([resolved: ["skey", "action"]])
            // scopeProvenanceRequested omitted: this is the pre-migration shape.
        )
        XCTAssertNil(
            legacy.requestedBaseline(),
            """
            a row with requested bytes but no requested-side provenance has no \
            baseline to re-derive from; substituting an empty map would silently \
            close both §9-D23 fences on a live grant
            """
        )

        // The same binding once the column exists: a baseline appears, carrying
        // the requested-keyed bits verbatim.
        let migrated = OAuthClientBinding(
            issuer: legacy.issuer,
            clientID: legacy.clientID,
            redirectURI: legacy.redirectURI,
            scopes: legacy.scopes,
            scopesRequested: legacy.scopesRequested,
            scopeProvenance: legacy.scopeProvenance,
            scopeProvenanceRequested: OAuthScopeProvenance([requested: ["skey", "action"]])
        )
        let baseline = try XCTUnwrap(migrated.requestedBaseline())
        XCTAssertEqual(baseline.scopes, ["atproto", requested])
        XCTAssertEqual(baseline.scopeProvenance?.statedKeys(for: requested), ["skey", "action"])

        // And the total case §6.7's NULL rule covers: nothing was ever rewritten,
        // so `scope_provenance` is already keyed by the requested strings.
        let untouched = OAuthClientBinding(
            issuer: legacy.issuer,
            clientID: legacy.clientID,
            redirectURI: legacy.redirectURI,
            scopes: ["atproto", requested],
            scopeProvenance: OAuthScopeProvenance([requested: ["skey", "action"]])
        )
        XCTAssertEqual(
            try XCTUnwrap(untouched.requestedBaseline()).scopeProvenance?
                .statedKeys(for: requested),
            ["skey", "action"],
            "a pre-migration row whose grant was never rewritten re-derives from its own provenance"
        )
    }

    // MARK: - Helpers

    private static func write(_ collection: String) -> SpaceScopeTarget {
        SpaceScopeTarget(
            type: spaceType,
            authority: PermissionedScopeFixture.subject,
            skey: "own",
            operation: .write(.create, collection: collection)
        )
    }

    /// The family value a mint of `client` produces, assembled from that mint's
    /// own result.
    ///
    /// `rederivedGrant(for:)` is a function of the family value alone — it
    /// re-derives from the binding it is handed and compares against that same
    /// binding — so a value assembled here answers exactly as the stored row
    /// would, and `familyID` never reaches the decision.
    ///
    /// Both provenance maps are empty because they genuinely are: every scope in
    /// these fixtures is a bare grant with no parameters written, which is the
    /// case §9-D23 calls "nothing was stated". They are supplied as empty maps
    /// rather than omitted, since `nil` on the requested side is the distinct
    /// pre-migration signal.
    private static func family(
        mintedBy issued: OAuthTokenGrantResult
    ) -> OAuthTokenFamily {
        OAuthTokenFamily(
            familyID: UUID(),
            subject: issued.subject,
            binding: OAuthClientBinding(
                issuer: PermissionedScopeFixture.issuer.absoluteString,
                clientID: "http://localhost",
                redirectURI: PermissionedScopeFixture.redirectURI.absoluteString,
                scopes: issued.scopes,
                scopesRequested: issued.scopesRequested,
                scopeProvenance: OAuthScopeProvenance(),
                scopeProvenanceRequested: OAuthScopeProvenance()
            ),
            expiresAt: Date().addingTimeInterval(3_600)
        )
    }
}

/// A stub resolver whose documents can be **replaced** between calls, which is
/// what makes a narrowing observable at all. The immutable stub in
/// `SwanOAuthTests` cannot express "the authority changed its mind", and that is
/// the entire subject of this suite.
final class MutableStubLexiconResolver: SwanLexiconResolving, @unchecked Sendable {
    private let lock = NSLock()
    private var documents: [String: SwanLexiconDocument]
    private var _resolutions = 0

    init(_ documents: [String: SwanLexiconDocument]) { self.documents = documents }

    func replace(_ documents: [String: SwanLexiconDocument]) {
        lock.withLock { self.documents = documents }
    }

    var resolutionCount: Int { lock.withLock { _resolutions } }

    func resolve(_ nsid: String) async throws -> SwanLexiconResolution {
        let document = lock.withLock { () -> SwanLexiconDocument? in
            _resolutions += 1
            return documents[nsid]
        }
        guard let document else { return .unresolvable }
        return .resolved(
            document,
            sourceURI: "at://did:plc:authorityauthorityauthority/com.atproto.lexicon.schema/\(nsid)",
            verifiedCID: "bafyreistubstubstubstubstubstubstubstubstubstubstubstubstub"
        )
    }
}
