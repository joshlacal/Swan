import Foundation
import XCTest
@testable import SwanCore
@testable import SwanHTTP
@testable import SwanOAuth
import SwanSQLite

/// **§9-D20 — BLOCKER** — plus the rest of §7.5's migration tests.
///
/// §9-D20 fixes a contradiction that made refresh unworkable for essentially
/// every grant Swan issues. `DurableOAuthTokenService.swift:770` compares the
/// client's re-presented scopes against `family.binding.scopes`; §9-D8 made
/// `binding.scopes` hold the **resolved** grant, while the client re-presents
/// the bytes it originally **requested**. For `authority=self` — the grammar's
/// default, and therefore the common case — those two deliberately differ, so
/// the comparison could never succeed.
///
/// The fix changes the OPERAND, not the comparison: the baseline becomes
/// `family.scopes_requested ?? family.scopes`.
///
/// These tests are **red before that operand change and green after**, which is
/// the whole reason they replace the previous "non-canonical parameter order
/// still refreshes" vector. That one exercised the formatter, not the operand,
/// and would have gone green while every `self`-bearing grant in production
/// failed to refresh. It is kept below as a separate, additional case — it is a
/// real property, it is simply not the one that breaks.
final class ScopeRefreshSurvivalMigrationTests: XCTestCase, @unchecked Sendable {
    private static let spaceType = "app.example.forum"

    /// Every client here is `.localhostBridge`, and it is not a shortcut.
    /// §9-D20's binding comparison lives on `redeemLocalhostPublicRefresh`
    /// (`DurableOAuthTokenService.swift:770`), which validates its `clientID` as
    /// a localhost development client and refuses anything else. A remote client
    /// fails with `invalid localhost development client_id` — a harness error
    /// that would masquerade as the refresh failure this suite exists to detect.

    // MARK: - §9-D20: refresh survives `self` resolution

    /// Shape A: `authority` **omitted**, so it defaults to `self`
    /// (`space-permission.ts:183`). This is the shape most clients actually send,
    /// and the one a test written against a fully-specified
    /// `authority=did:plc:…` grant cannot see the defect in at all (§8.3 step 3).
    func testRefreshSucceedsWithOriginalBytesWhenAuthorityDefaultedToSelf() async throws {
        try await assertRefreshSurvivesSelfResolution(
            requested: "space:\(Self.spaceType)?action=read_self",
            label: "defaulted-self"
        )
    }

    /// Shape B: `authority=self` written **literally**. Same resolution, but it
    /// reaches it through the parser's literal arm rather than its default arm —
    /// §7.5 requires both, since a fix that preserved only one would still strand
    /// half the clients.
    func testRefreshSucceedsWithOriginalBytesWhenAuthorityWasLiteralSelf() async throws {
        try await assertRefreshSurvivesSelfResolution(
            requested: "space:\(Self.spaceType)?authority=self&skey=*&action=read_self",
            label: "literal-self"
        )
    }

    private func assertRefreshSurvivesSelfResolution(
        requested: String,
        label: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async throws {
        let client = try PermissionedScopeClient(scopes: [requested], kind: .localhostBridge)
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }

        let issued = try await fixture.mint(client: client, proofID: "d20-\(label)-mint")

        // Step 2 — assert the two sets DIFFER. A run where they happen to be
        // equal is not exercising this path, so the inequality is asserted rather
        // than merely read: `scopes` holds the resolved DID, the client's
        // requested bytes still say `self` (or say nothing).
        XCTAssertNotEqual(
            issued.scopes,
            client.scopeSet,
            """
            Requested and granted scopes are identical, so `self` was never \
            resolved and this test cannot detect the §9-D20 defect. Either §6.4's \
            mint-time resolution is missing, or the requested scope no longer \
            carries `self`.
            """,
            file: file,
            line: line
        )
        XCTAssertTrue(
            issued.scopes.contains { $0.contains("authority=\(PermissionedScopeFixture.subject)") },
            "mint must persist the resolved authority (§6.4)",
            file: file,
            line: line
        )

        // Step 3 — refresh with the ORIGINAL REQUESTED bytes. Not the resolved
        // ones: the client has never seen those, and asking it to present them
        // would be asking it to guess Swan's own rewrite.
        let refreshToken = try XCTUnwrap(issued.refreshToken, file: file, line: line)
        let session = try client.session(proofID: "d20-\(label)-refresh")
        let rotated: OAuthTokenPair
        do {
            rotated = try await fixture.runtime.tokenService.redeemLocalhostPublicRefresh(
                refreshToken,
                clientID: client.clientID,
                dpopProof: session.dpopProof,
                requestedScopes: client.scopeSet
            )
        } catch {
            XCTFail(
                """
                REFRESH BROKEN FOR EVERY `self`-BEARING GRANT (§9-D20). The client \
                re-presented exactly the bytes it requested \
                (\(client.scopeSet.sorted())) and was refused with \(error). The \
                binding comparison at DurableOAuthTokenService.swift:770 must run \
                against `family.scopes_requested ?? family.scopes`, never against \
                `family.binding.scopes`, which under §9-D8 holds the \
                post-resolution value.
                """,
                file: file,
                line: line
            )
            return
        }

        // Step 4 — the rotated family still carries the RESOLVED grant. Refresh
        // must not quietly rewrite the grant back to the requested bytes; that
        // would un-resolve `self` and the token would match nothing (M22).
        let grant = try await fixture.runtime.tokenService.validateAccess(
            rotated.accessToken,
            proof: session.dpopProof
        )
        XCTAssertEqual(
            grant.scopes,
            issued.scopes,
            "rotation must preserve the resolved grant, not replace it with the requested bytes",
            file: file,
            line: line
        )
    }

    /// The additional, weaker property §7.5 says to keep as a **separate** case:
    /// formatter stability across a non-canonical parameter order. Real, worth
    /// holding, and explicitly not the case that breaks — which is why it is not
    /// allowed to stand in for the two tests above.
    func testRefreshAlsoSurvivesANonCanonicalParameterOrder() async throws {
        // Corpus row: `?skey=default&authority=did:…` canonicalises with
        // `authority` first. The client re-presents its own ordering.
        let requested =
            "space:\(Self.spaceType)?skey=default&authority=\(PermissionedScopeFixture.subject)&action=read"
        let client = try PermissionedScopeClient(scopes: [requested], kind: .localhostBridge)
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }

        let issued = try await fixture.mint(client: client, proofID: "d20-order-mint")
        let refreshToken = try XCTUnwrap(issued.refreshToken)
        let session = try client.session(proofID: "d20-order-refresh")
        _ = try await fixture.runtime.tokenService.redeemLocalhostPublicRefresh(
            refreshToken,
            clientID: client.clientID,
            dpopProof: session.dpopProof,
            requestedScopes: client.scopeSet
        )
    }

    /// Widening must still be refused. The operand change is a *correction* of
    /// which bytes are compared, not a relaxation of the comparison — if this
    /// regresses, §9-D20 was implemented as "stop checking".
    func testRefreshStillRefusesAWidenedScopeSet() async throws {
        let requested = "space:\(Self.spaceType)?action=read_self"
        let client = try PermissionedScopeClient(scopes: [requested], kind: .localhostBridge)
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }

        let issued = try await fixture.mint(client: client, proofID: "d20-widen-mint")
        let refreshToken = try XCTUnwrap(issued.refreshToken)
        let session = try client.session(proofID: "d20-widen-refresh")
        do {
            _ = try await fixture.runtime.tokenService.redeemLocalhostPublicRefresh(
                refreshToken,
                clientID: client.clientID,
                dpopProof: session.dpopProof,
                requestedScopes: client.scopeSet.union(["atproto"])
            )
            XCTFail("refresh accepted a widened scope set")
        } catch {
            // Expected: the comparison is still raw-string equality over the set.
        }
    }

    // MARK: - §7.5: the junk companion, and the additive column

    /// §7.5 item 4, and the reason stage G's re-parse must be **additive only**.
    ///
    /// `validScope` (`OAuthControlStore.swift:2345-2350`) is the only *per
    /// element* gate on a persisted scope: non-empty, byte cap, no whitespace, no
    /// control characters — and nothing else. `hasATProtocolResourceScope` is an
    /// OR over the set, not an all-satisfy over its elements, so a live row may
    /// legitimately hold an unparseable companion beside a good scope.
    ///
    /// Rotating such a family must **succeed**. Under a full re-parse on
    /// rotation it would fail, and the session would be locked out permanently —
    /// a live-session outage caused by a scope the client is not even using.
    func testRotationSucceedsForAFamilyHoldingAnUnparseableCompanionScope() throws {
        // Lexically legal for `validScope` (no whitespace, no controls, short),
        // semantically unparseable under the new grammar: the type is not an NSID
        // and the authority is not a DID. §7.5 item 3 names this exact shape.
        let junk = "space:notannsid?authority=notadid&skey=k&action=read"

        // FINDING, and the reason this test cannot run today: a family holding an
        // unparseable companion can no longer be CREATED through the request
        // path at all. §9-D5 rejects an unparseable *requested* scope at PAR, so
        // mint refuses the whole request rather than persisting the junk beside
        // the good scope. That is correct behaviour, and it narrows §7.5's
        // concern usefully: such a row can now only exist as a LEGACY row
        // written by an older binary. Which is exactly the row this test needs
        // and cannot construct.
        //
        // Seeding one directly is not reachable from a test either:
        // `DurableOAuthTokenService.tokenDigests(for:)` and `digest(_:purpose:)`
        // are `private` (`:1059`, `:1069`, `:1121`), so a test cannot compute the
        // digests for a token it could then present. `OAuthClientBinding` itself
        // is fully public and carries `scopesRequested` and `scopeProvenance`, so
        // the only missing piece is a seam.
        //
        // REQUESTED OF L2: an internal test seam mirroring L3's
        // `accountOAuthForTesting` — something like
        // `seedTokenFamilyForTesting(subject:binding:now:) -> OAuthTokenPair`,
        // which writes the family and returns the raw tokens. With it, this test
        // becomes: seed {atproto, junk} with `scopeProvenance: nil` (a
        // pre-migration row), rotate, assert the rotation SUCCEEDS and the junk
        // is retained. Under a stage-G full re-parse it would fail and lock the
        // session out permanently — a live-session outage caused by a scope the
        // client is not even using.
        throw XCTSkip(
            """
            Needs a durable-row seeding seam. A family holding \(junk) cannot be             minted (§9-D5 rejects it at PAR — correct) and cannot be seeded             (token digest helpers are private). Requested of L2:             `seedTokenFamilyForTesting(subject:binding:now:)`. Until then the             additive-only stage-G property is UNVERIFIED, not passing.
            """
        )
    }

    /// §9-D5's match layer, on the same live grant: a stored string a future
    /// binary cannot parse must be able to fail a request neither OPEN nor with a
    /// crash. It grants nothing, silently, and the good scope beside it still
    /// works.
    func testAnUnparseableHeldScopeGrantsNothingAndBreaksNothing() throws {
        // Asserted on a directly-constructed permissions value rather than on a
        // minted token, and that is now the ONLY faithful shape. §9-D5 splits
        // this across two layers: the REQUEST layer rejects an unparseable scope
        // at PAR, so such a set can no longer be minted at all; the MATCH layer
        // — this one — must hold for a set that is ALREADY persisted, i.e. a row
        // an older binary wrote. Routing it through mint would exercise the
        // request layer's rejection and label it the match layer's tolerance.
        let junk = "space:notannsid?authority=notadid&skey=k&action=read"
        let good = "space:\(Self.spaceType)?authority=\(PermissionedScopeFixture.subject)&skey=*&action=read"
        let permissions = SwanScopePermissions(
            rawScopes: ["atproto", good, junk],
            subject: PermissionedScopeFixture.subject
        )

        // Neither fails open nor crashes: recorded for logging, greppable, and
        // granting nothing.
        XCTAssertEqual(Set(permissions.rejected.keys), [junk])
        XCTAssertTrue(
            permissions.rawScopes.contains(junk),
            "the raw string survives verbatim — persistence and audit never see a re-serialised value"
        )
        XCTAssertFalse(
            permissions.allowsSpace(
                SpaceScopeTarget(
                    type: "notannsid",
                    authority: "notadid",
                    skey: "k",
                    operation: .read(aggregate: false, collection: nil)
                )
            ),
            "an unparseable held scope must grant exactly nothing"
        )
        // The good scope beside it is unaffected — a rejected element must not
        // poison the set. Ordinary single-space read, not an aggregate surface:
        // an aggregate read would fail on the §6.5.5 hardening rather than on
        // anything to do with the junk companion.
        XCTAssertTrue(
            permissions.allowsSpace(
                SpaceScopeTarget(
                    type: Self.spaceType,
                    authority: PermissionedScopeFixture.subject,
                    skey: "anything",
                    operation: .read(aggregate: false, collection: nil)
                )
            ),
            "a rejected element must not poison the rest of the set"
        )

        // The other half of §9-D5, asserted in the same file so the pair is
        // visible: the same string is REFUSED at the request layer rather than
        // silently dropped.
        XCTAssertThrowsError(
            try AtprotoScope.parse(junk),
            "§9-D5 request layer: an unparseable requested scope is rejected, never narrowed away"
        )
    }

    /// §7.5's persistence replay. Runs the new parser over every distinct scope
    /// string a family row can hold and **records** the rejected list rather than
    /// asserting it is empty.
    ///
    /// The first draft asserted zero on a false premise — that `isQualified`
    /// gates every INSERT. It does not: that check is an OR over the set. The
    /// expected result is a small enumerable list, and a non-empty list is a
    /// blocker only when a rejected string is the *only* scope in its family row,
    /// since a held unparseable scope grants nothing (§9-D5).
    ///
    /// Against a live database this replay runs over `SELECT DISTINCT scopes`.
    /// Here it runs over the same predicate applied to a seeded corpus of the
    /// shapes §7.5 enumerates, so the classification logic itself is tested; the
    /// production sweep is §8 step 1 and is executed against prod, not in CI.
    func testPersistenceReplayClassifiesRatherThanRejects() throws {
        let rows: [(scopes: Set<String>, blocking: Bool)] = [
            // Ordinary rows, nothing rejected.
            (["atproto"], false),
            (["atproto", "space:\(Self.spaceType)?authority=did:plc:abcdefghijklmnopqrstuvwx&skey=*&action=read"], false),
            // A junk companion beside a good scope: rejected, NOT blocking.
            (["atproto", "space:notannsid?authority=notadid&skey=k&action=read"], false),
            // The only scope in the row is unparseable: BLOCKING — that family
            // grants nothing at all once the new grammar ships.
            (["space:notannsid?authority=notadid&skey=k&action=read"], true),
        ]
        for row in rows {
            var rejected: [String] = []
            for scope in row.scopes.sorted() {
                do { _ = try AtprotoScope.parse(scope) } catch { rejected.append(scope) }
            }
            let blocking = !rejected.isEmpty && rejected.count == row.scopes.count
            XCTAssertEqual(
                blocking,
                row.blocking,
                """
                replay classification wrong for \(row.scopes.sorted()); rejected \
                \(rejected). A rejected string blocks only when it is the ONLY \
                scope in its family row (§7.5 item 2).
                """
            )
        }
    }

    /// §7.5's additive-column back-compat, on a live authorization path.
    ///
    /// A pre-migration row has `scopes_requested IS NULL`, which decodes as
    /// "requested == stored" — not as "unknown". Since §9-D20 makes the refresh
    /// baseline `scopes_requested ?? scopes`, that rule is what makes the
    /// fallback **total**, and §8.1's "old tokens are not re-minted" promise
    /// depends on it.
    ///
    /// The pre-migration shape is a grant that never had `self` resolved into it,
    /// i.e. one written entirely in literal values. It must refresh unchanged.
    func testPreMigrationShapedGrantRefreshesThroughTheNullFallback() async throws {
        let requested =
            "space:\(Self.spaceType)?authority=\(PermissionedScopeFixture.subject)&skey=*&action=read"
        let client = try PermissionedScopeClient(scopes: ["atproto", requested], kind: .localhostBridge)
        let fixture = try await PermissionedScopeFixture.make()
        defer { Task { await fixture.tearDown() } }

        let issued = try await fixture.mint(client: client, proofID: "null-fallback-mint")
        // Nothing was resolved, so requested and stored are equal — exactly the
        // state a NULL `scopes_requested` encodes.
        XCTAssertEqual(issued.scopes, client.scopeSet)

        let refreshToken = try XCTUnwrap(issued.refreshToken)
        let session = try client.session(proofID: "null-fallback-refresh")
        let rotated = try await fixture.runtime.tokenService.redeemLocalhostPublicRefresh(
            refreshToken,
            clientID: client.clientID,
            dpopProof: session.dpopProof,
            requestedScopes: client.scopeSet
        )
        let grant = try await fixture.runtime.tokenService.validateAccess(
            rotated.accessToken,
            proof: session.dpopProof
        )
        XCTAssertEqual(grant.scopes, client.scopeSet, "a pre-migration row must refresh unchanged")
    }
}
