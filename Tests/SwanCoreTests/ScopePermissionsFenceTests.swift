import Foundation
import XCTest
@testable import SwanCore

/// Resource-plane enforcement tests: the accept set of `hasResourceScope`, and
/// the two provenance fences that are load-bearing **because**
/// `isIssuableQualified` is retired (§9-D21).
///
/// These tests are deliberately written against DURABLE provenance supplied as
/// an input, never re-derived from the scope string. §9-D23: "A parse ->
/// matcher test passes with the bug present, which is why those tests exist in
/// that shape." The headline case here is
/// `testDelegationFenceRefusesAMintResolvedSelfAuthority`, which uses the exact
/// persisted string a `self` grant becomes after mint.
final class ScopePermissionsFenceTests: XCTestCase {
    private let user = "did:plc:user"

    private func permissions(
        _ scope: String,
        stated: Set<String>,
        subject: String? = "did:plc:user"
    ) -> SwanScopePermissions {
        SwanScopePermissions(
            rawScopes: [scope],
            subject: subject,
            statedKeys: [scope: stated]
        )
    }

    private func read(aggregate: Bool, collection: String?) -> SpaceScopeTarget {
        SpaceScopeTarget(
            type: "x.y.z",
            authority: user,
            skey: "self",
            operation: .read(aggregate: aggregate, collection: collection)
        )
    }

    private func delegation(_ type: String = "x.y.z", skey: String = "self") -> SpaceScopeTarget {
        SpaceScopeTarget(
            type: type,
            authority: user,
            skey: skey,
            operation: .delegationExchange
        )
    }

    // MARK: - hasResourceScope: `atproto` OR `space:`, and nothing else

    func testResourceFloorAcceptsOnlyAtprotoAndSpace() {
        XCTAssertTrue(
            SwanScopePermissions(rawScopes: ["atproto"], subject: user).hasResourceScope
        )
        XCTAssertTrue(
            SwanScopePermissions(
                rawScopes: ["space:x.y.z?authority=\(user)&skey=self&action=read"],
                subject: user
            ).hasResourceScope
        )
    }

    /// §6.1 and §9-D21: after the localhost bridge stops gating on
    /// `isIssuableQualified`, six families plus three `transition:*` values
    /// become newly registrable. None of them may satisfy the resource floor on
    /// its own, because `SwanSpaceXRPC.swift:77`,
    /// `SwanSpaceBlobXRPC.swift:340` and `SwanSpaceRepositorySyncXRPC.swift:288`
    /// check nothing further. This is §7.4's per-family acceptance assertion at
    /// the facade layer.
    func testResourceFloorRefusesEveryNonSpaceFamilyAlone() {
        let newlyAdmissible = [
            "account:email?action=manage",
            "blob:image/*",
            "identity:handle",
            "repo:app.bsky.feed.post?action=create",
            "rpc:app.bsky.feed.getTimeline?aud=*",
            "include:app.example.bundle",
            "transition:email",
            "transition:generic",
            "transition:chat.bsky",
        ]
        for scope in newlyAdmissible {
            XCTAssertFalse(
                SwanScopePermissions(rawScopes: [scope], subject: user).hasResourceScope,
                "\(scope) must not satisfy the resource floor on its own"
            )
        }
        // Nor collectively.
        XCTAssertFalse(
            SwanScopePermissions(rawScopes: Set(newlyAdmissible), subject: user).hasResourceScope
        )
    }

    func testBaseScopeIsNarrowerThanTheResourceFloor() {
        let spaceOnly = SwanScopePermissions(
            rawScopes: ["space:x.y.z?authority=\(user)&skey=self&action=read"],
            subject: user
        )
        XCTAssertTrue(spaceOnly.hasResourceScope)
        // `SQLitePreMigratedAccountDirectory.swift:272` depends on this
        // remaining the narrower predicate (§6.5.1: do not "fix" it).
        XCTAssertFalse(spaceOnly.hasBaseATProtocolScope)
    }

    // MARK: - The delegation fence (§5.6.3, amended per Erratum 02)

    /// Post-amendment: a mint-resolved `self` authority with a STATED action
    /// is exchangeable. The §9-D23 durable-provenance property is now
    /// witnessed by `testDelegationFenceRefusesADefaultedActionList` — the
    /// stated-action bit is still read from the durable record, never
    /// reconstructed from the persisted string.
    func testDelegationFenceAcceptsAMintResolvedSelfAuthorityWithStatedAction() {
        let persisted = "space:x.y.z?authority=\(user)&skey=*&action=read"
        let permissions = permissions(persisted, stated: ["skey", "action"])
        XCTAssertTrue(permissions.allowsSpace(delegation(skey: "*")))
    }

    func testDelegationFenceAcceptsAFullyStatedReadOnlyGrant() {
        let scope = "space:x.y.z?authority=\(user)&skey=self&action=read"
        let permissions = permissions(scope, stated: ["authority", "skey", "action"])
        XCTAssertTrue(permissions.allowsSpace(delegation()))
    }

    /// Absent provenance is FAIL CLOSED. A missing bit denies; it never grants.
    func testDelegationFenceRefusesWhenProvenanceIsAbsentEntirely() {
        let scope = "space:x.y.z?authority=\(user)&skey=self&action=read"
        XCTAssertFalse(
            SwanScopePermissions(rawScopes: [scope], subject: user)
                .allowsSpace(delegation())
        )
    }

    /// The surviving §9-D21 witness. A DEFAULTED action list contains `read`
    /// and must still refuse — a bare `space:<type>` never exchanges.
    func testDelegationFenceRefusesADefaultedActionList() {
        let bare = "space:x.y.z"
        XCTAssertFalse(
            permissions(bare, stated: []).allowsSpace(delegation(skey: "*"))
        )
    }

    /// Amended clause 1: `action` need only CONTAIN `read`. Extra write verbs
    /// are not an escalation for a read credential the caller could already
    /// exceed with its write grants.
    func testDelegationFenceAcceptsAStatedMultiActionGrant() {
        let scope = "space:x.y.z?authority=\(user)&skey=self&action=read&action=create"
        XCTAssertTrue(
            permissions(scope, stated: ["authority", "skey", "action"])
                .allowsSpace(delegation())
        )
    }

    /// **The Erratum 02 concession, pinned deliberately.** A
    /// collection-qualified read grant now exchanges for a whole-space read
    /// credential — upstream's semantics (`space-permission.ts:104-107`). The
    /// original hardening's analysis was correct; the protocol's credential
    /// model cannot carry the collection restriction, and interoperability
    /// requires the lossy conversion. If a future credential model becomes
    /// collection-aware, revisit — do not simply flip this back.
    func testDelegationFenceAcceptsACollectionQualifiedGrant() {
        for collection in ["*", "app.bsky.feed.post"] {
            let scope = "space:x.y.z?authority=\(user)&skey=self&action=read&collection=\(collection)"
            XCTAssertTrue(
                permissions(scope, stated: ["authority", "skey", "action", "collection"])
                    .allowsSpace(delegation()),
                "collection=\(collection) is exchangeable post-Erratum-02"
            )
        }
    }

    /// Amended: a manage list alongside a stated read no longer disqualifies.
    func testDelegationFenceAcceptsAStatedManageList() {
        let scope = "space:x.y.z?authority=\(user)&skey=self&action=read&manage=delete"
        XCTAssertTrue(
            permissions(scope, stated: ["authority", "skey", "action", "manage"])
                .allowsSpace(delegation())
        )
    }

    /// Amended clause 2 (option 2 of the ruling): the grant's space type must
    /// be concrete. A wildcard-type grant must not mint credentials for
    /// arbitrary space types, even with a stated read.
    func testDelegationFenceRefusesAWildcardTypeGrant() {
        let scope = "space:*?authority=\(user)&skey=self&action=read"
        XCTAssertFalse(
            permissions(scope, stated: ["authority", "skey", "action"])
                .allowsSpace(delegation())
        )
    }

    /// Unstated authority/skey no longer disqualify — value coverage of the
    /// tuple is still enforced by `matches` (§5.6.3 steps 1-3), and the only
    /// admissible authority for a defaulted grant is the resolved subject.
    func testDelegationFenceAcceptsUnstatedAuthorityAndSkey() {
        let scope = "space:x.y.z?authority=\(user)&skey=self&action=read"
        XCTAssertTrue(
            permissions(scope, stated: ["skey", "action"]).allowsSpace(delegation())
        )
        XCTAssertTrue(
            permissions(scope, stated: ["authority", "action"]).allowsSpace(delegation())
        )
    }

    /// The verbatim Bulleted `spaceAccess` expansion — the shape that was
    /// 401ing on getDelegationToken before Erratum 02.
    func testDelegationFenceAcceptsTheBulletedSpaceAccessExpansionShape() {
        let scope = "space:app.bulleted.space?authority=*"
            + "&collection=app.bulleted.node&collection=app.bulleted.note"
            + "&collection=app.bulleted.outline&collection=app.bulleted.mirror"
            + "&collection=app.bulleted.comment&collection=app.bulleted.commentPolicy"
            + "&action=read&action=create&action=update&action=delete"
        let permissions = permissions(scope, stated: ["authority", "collection", "action"])
        XCTAssertTrue(
            permissions.allowsSpace(delegation("app.bulleted.space", skey: "3m2abcdefgh22"))
        )
        // A different space type still refuses (§5.6.3 step 1).
        XCTAssertFalse(permissions.allowsSpace(delegation("app.other.space")))
    }

    /// The fence does not replace the tuple match: a fully stated read-only
    /// grant for a DIFFERENT space still refuses (§5.6.3 steps 1-3).
    func testDelegationFenceStillRequiresTheTupleToMatch() {
        let scope = "space:x.y.z?authority=\(user)&skey=self&action=read"
        let permissions = permissions(scope, stated: ["authority", "skey", "action"])
        XCTAssertFalse(permissions.allowsSpace(delegation("other.type.here")))
        XCTAssertFalse(permissions.allowsSpace(delegation(skey: "different")))
    }

    /// `read_self` is not exchangeable, even fully stated — §7.2's D7 row: the
    /// fence does not move with the retired gate.
    func testDelegationFenceRefusesReadSelf() {
        let scope = "space:x.y.z?authority=\(user)&skey=self&action=read_self"
        XCTAssertFalse(
            permissions(scope, stated: ["authority", "skey", "action"])
                .allowsSpace(delegation())
        )
    }

    // MARK: - Reads ignore collection restrictions

    /// Proposal 0016 makes reads all-or-nothing at the space boundary.
    /// An explicitly named collection restricts writes, never record or sync reads.
    func testReadAndSyncAcceptACollectionQualifiedGrant() {
        let scope = "space:x.y.z?authority=\(user)&skey=self&action=read&collection=app.example.records"
        let permissions = permissions(
            scope,
            stated: ["authority", "skey", "action", "collection"]
        )

        XCTAssertTrue(
            permissions.allowsSpace(read(aggregate: false, collection: "app.example.records"))
        )
        XCTAssertTrue(
            permissions.allowsSpace(read(aggregate: false, collection: nil)),
            "a collection-qualified grant must satisfy a single-blob read"
        )
        XCTAssertTrue(
            permissions.allowsSpace(read(aggregate: true, collection: nil)),
            "a collection-qualified grant must satisfy an aggregate read"
        )
        XCTAssertTrue(
            permissions.allowsSpace(read(aggregate: false, collection: "app.other.records"))
        )
    }

    /// The positive controls, so the clause above cannot be satisfied by a
    /// matcher that simply refuses every aggregate read.
    func testAggregateReadAcceptsUnqualifiedAndWildcardCollectionGrants() {
        let stated: Set<String> = ["authority", "skey", "action"]
        // An empty collection list names no WRITE targets but constrains no
        // read (`space-permission.ts:193-198`), so it covers an aggregate read.
        let unqualified = "space:x.y.z?authority=\(user)&skey=self&action=read"
        XCTAssertTrue(
            permissions(unqualified, stated: stated)
                .allowsSpace(read(aggregate: true, collection: nil))
        )
        // `collection=*` covers every collection explicitly.
        let wildcard = "space:x.y.z?authority=\(user)&skey=self&action=read&collection=*"
        XCTAssertTrue(
            permissions(wildcard, stated: stated.union(["collection"]))
                .allowsSpace(read(aggregate: true, collection: nil))
        )
    }

    // MARK: - The listing fence (§6.1)

    func testListingFenceAcceptsAFullyStatedWildcardSkeyReadGrant() {
        let scope = "space:x.y.z?authority=\(user)&skey=*&action=read"
        let permissions = permissions(scope, stated: ["authority", "skey", "action"])
        XCTAssertTrue(permissions.allowsSpaceListing(type: "x.y.z", authority: user))
    }

    /// **The §9-D23 mirror case.** Canonical serialisation deletes values equal
    /// to their defaults, so a stated `skey=*` disappears from the string. If
    /// provenance were re-derived from the string the fence could never fire
    /// again. Read from the durable record it still does.
    func testListingFenceSurvivesCanonicalisationOfAStatedWildcardSkey() {
        // What canonicalisation leaves behind: `skey=*` elided as default-equal.
        let canonical = "space:x.y.z?authority=\(user)&action=read"
        let permissions = permissions(canonical, stated: ["authority", "skey", "action"])
        XCTAssertTrue(permissions.allowsSpaceListing(type: "x.y.z", authority: user))
    }

    /// §6.1 AMENDED: a stated `action=read` grant lists even when `skey` was
    /// never stated — the original literal-`skey=*` requirement made the fence
    /// unreachable by real clients (no upstream client states `skey` at all).
    func testListingFenceAcceptsAStatedReadGrantWithoutStatedSkey() {
        let canonical = "space:x.y.z?authority=\(user)&action=read"
        let permissions = permissions(canonical, stated: ["authority", "action"])
        XCTAssertTrue(permissions.allowsSpaceListing(type: "x.y.z", authority: user))
    }

    /// The surviving §9-D21 witness: `action` defaults to a list containing
    /// `read`, so a bare grant that never STATED an action must not list.
    func testListingFenceRefusesADefaultedActionList() {
        let bare = "space:x.y.z"
        XCTAssertFalse(
            permissions(bare, stated: []).allowsSpaceListing(type: "x.y.z", authority: user)
        )
    }

    /// §6.1 AMENDED: a stated `collection` no longer disqualifies —
    /// bulleted.app's `spaceAccess` permission set expands to exactly this
    /// shape (stated authority/collection/action, four actions). A `manage`
    /// grant whose action list was never stated still fails the witness.
    func testListingFenceAcceptsStatedCollectionAndRefusesUnstatedActionManage() {
        let withCollection = "space:x.y.z?authority=\(user)&skey=*&action=read&collection=*"
        XCTAssertTrue(
            permissions(withCollection, stated: ["authority", "skey", "action", "collection"])
                .allowsSpaceListing(type: "x.y.z", authority: user)
        )
        let withManage = "space:x.y.z?authority=\(user)&skey=*&manage=update"
        XCTAssertFalse(
            permissions(withManage, stated: ["authority", "skey", "manage"])
                .allowsSpaceListing(type: "x.y.z", authority: user)
        )
    }

    /// §6.1 AMENDED: `read_self` suffices — upstream accepts it for every
    /// `space.get*/list*` route (`space/util.ts:109-127`), and the list route
    /// self-scopes to the token's own subject.
    func testListingFenceAcceptsAStatedReadSelfGrant() {
        let scope = "space:x.y.z?authority=\(user)&action=read_self"
        let permissions = permissions(scope, stated: ["authority", "action"])
        XCTAssertTrue(permissions.allowsSpaceListing(type: "x.y.z", authority: user))
    }

    /// The bulleted.app `spaceAccess` expansion, verbatim: wildcard authority,
    /// six collections, four actions. Lists its declared type for a request
    /// that names no authority (an unfiltered-authority request needs the
    /// wildcard grant this set carries).
    func testListingFenceAcceptsTheBulletedSpaceAccessExpansionShape() {
        let scope = "space:app.bulleted.space?authority=*"
            + "&collection=app.bulleted.node&collection=app.bulleted.note"
            + "&collection=app.bulleted.outline&collection=app.bulleted.mirror"
            + "&collection=app.bulleted.comment&collection=app.bulleted.commentPolicy"
            + "&action=read&action=create&action=update&action=delete"
        let permissions = permissions(scope, stated: ["authority", "collection", "action"])
        XCTAssertTrue(permissions.allowsSpaceListing(type: "app.bulleted.space", authority: nil))
        XCTAssertTrue(permissions.allowsSpaceListing(type: "app.bulleted.space", authority: user))
        // Still no cross-type listing, and no unfiltered-type listing.
        XCTAssertFalse(permissions.allowsSpaceListing(type: "app.other.space", authority: nil))
        XCTAssertFalse(permissions.allowsSpaceListing(type: nil, authority: nil))
    }

    /// `aggregateDimension` (`SwanCore.swift:324-327`): an omitted request
    /// dimension is the literal `*` target and requires a literal wildcard
    /// GRANT. The list route refuses to fetch broadly and then censor rows.
    func testListingFenceRefusesAWildcardRequestAgainstAConcreteGrant() {
        let scope = "space:x.y.z?authority=\(user)&skey=*&action=read"
        let permissions = permissions(scope, stated: ["authority", "skey", "action"])
        XCTAssertFalse(permissions.allowsSpaceListing(type: nil, authority: user))
        XCTAssertFalse(permissions.allowsSpaceListing(type: "x.y.z", authority: nil))
        XCTAssertFalse(permissions.allowsSpaceListing(type: nil, authority: nil))
    }

    func testListingFenceAcceptsAWildcardRequestAgainstAWildcardGrant() {
        let scope = "space:*?authority=*&skey=*&action=read"
        let permissions = permissions(scope, stated: ["authority", "skey", "action"])
        XCTAssertTrue(permissions.allowsSpaceListing(type: nil, authority: nil))
        XCTAssertTrue(permissions.allowsSpaceListing(type: "x.y.z", authority: user))
    }

    func testListingFenceRefusesAConcreteRequestForAnotherAuthority() {
        let scope = "space:x.y.z?authority=\(user)&skey=*&action=read"
        let permissions = permissions(scope, stated: ["authority", "skey", "action"])
        XCTAssertFalse(
            permissions.allowsSpaceListing(type: "x.y.z", authority: "did:plc:other")
        )
    }

    // MARK: - `self` fails closed without a subject

    /// `space_permission.rs:1579-1584`,
    /// `self_matches_nothing_without_a_subject`. A permissions value with no
    /// subject leaves `authority` at `.unresolvedSelf`, which matches nothing —
    /// including the listing fence, whose `aggregateDimension` sees the literal
    /// "self" and no request can equal it.
    func testUnresolvedSelfMatchesNothingWithoutASubject() {
        let scope = "space:x.y.z?authority=self&skey=self&action=read"
        let stated: Set<String> = ["authority", "skey", "action"]
        let unbound = permissions(scope, stated: stated, subject: nil)
        XCTAssertFalse(unbound.allowsSpace(delegation()))
        XCTAssertFalse(unbound.allowsSpaceListing(type: "x.y.z", authority: user))
        // ...but the floor is still satisfied: it is a `space:` grant.
        XCTAssertTrue(unbound.hasResourceScope)

        // Bound to the subject, the same grant resolves and matches.
        let bound = permissions(scope, stated: stated, subject: user)
        XCTAssertTrue(bound.allowsSpace(delegation()))
    }

    // MARK: - Denials stay opaque (§9-D6)

    /// An unparseable stored scope grants nothing and is recorded for logs; it
    /// must NOT propagate a `ScopeParseError` out of the facade, which would
    /// surface a denial as an `unavailable` 500.
    func testAnUnparseableStoredScopeIsRecordedAndGrantsNothing() {
        let permissions = SwanScopePermissions(
            rawScopes: ["atproto", "space:not a valid scope at all"],
            subject: user
        )
        XCTAssertEqual(permissions.rejected.count, 1)
        XCTAssertTrue(permissions.hasResourceScope)  // from `atproto`
        XCTAssertFalse(permissions.allowsSpace(delegation()))
    }

    /// `requireSpace` degrades an unrenderable target into the SAME opaque
    /// denial rather than throwing a formatting error (§6.1, §5.6.6). An
    /// attacker must not be able to distinguish "denied, well-formed target"
    /// from "denied, odd target".
    func testRequireSpaceDegradesAnUnrenderableTargetIntoAScopeDenied() {
        let permissions = SwanScopePermissions(rawScopes: ["atproto"], subject: user)
        let odd = SpaceScopeTarget(
            type: "x.y.z",
            authority: user,
            skey: "a key with spaces and \u{7f} control bytes",
            operation: .delegationExchange
        )
        XCTAssertThrowsError(try permissions.requireSpace(odd)) { error in
            XCTAssertTrue(
                error is ScopeDenied,
                "a formatting failure must not escape as anything but a denial"
            )
        }
    }

    /// Equality is over the inputs, and `rawScopes` is retained verbatim so
    /// persistence and audit surfaces never see a re-serialized value.
    func testRawScopesAreRetainedVerbatimAndEqualityIsOverInputs() {
        let wire = "space:x.y.z?skey=self&authority=\(user)&action=read"
        let value = permissions(wire, stated: ["authority", "skey", "action"])
        XCTAssertEqual(value.rawScopes, [wire])
        XCTAssertEqual(value, permissions(wire, stated: ["authority", "skey", "action"]))
        XCTAssertNotEqual(value, permissions(wire, stated: ["skey", "action"]))
    }
}

// MARK: - `--enable-spaces-open-interop` upstream defaults (SWAN-09)

extension ScopePermissionsFenceTests {
    private func upstream(_ scope: String, stated: Set<String> = []) -> SwanScopePermissions {
        SwanScopePermissions(
            rawScopes: [scope],
            subject: "did:plc:user",
            statedKeys: [scope: stated]
        ).withUpstreamSpaceDefaults()
    }

    private func exchange(type: String, authority: String) -> SpaceScopeTarget {
        SpaceScopeTarget(type: type, authority: authority, skey: "forum", operation: .delegationExchange)
    }

    /// The proposal's canonical bare grants exchange under upstream defaults
    /// and are refused by the hardened fence (positive and negative control).
    func testUpstreamDefaultsLetBareAndWildcardGrantsExchange() {
        let other = "did:plc:otherauthority"
        let cases: [(scope: String, target: SpaceScopeTarget)] = [
            ("space:com.example.forum?authority=*", exchange(type: "com.example.forum", authority: other)),
            ("space:com.example.forum", exchange(type: "com.example.forum", authority: "did:plc:user")),
            ("space:*?authority=*&action=read", exchange(type: "com.example.forum", authority: other)),
        ]
        for (scope, target) in cases {
            let stated: Set<String> = scope.contains("action=") ? ["authority", "action"] : (scope.contains("authority=") ? ["authority"] : [])
            XCTAssertTrue(upstream(scope, stated: stated).allowsSpace(target), scope)
            XCTAssertFalse(permissions(scope, stated: stated).allowsSpace(target), scope)
        }
    }

    /// Value coverage still applies: a defaulted `self` authority does not
    /// exchange for another authority's space, and a write-only grant never
    /// exchanges.
    func testUpstreamDefaultsKeepTupleMatchingAndRequireRead() {
        XCTAssertFalse(
            upstream("space:com.example.forum").allowsSpace(
                exchange(type: "com.example.forum", authority: "did:plc:otherauthority")
            )
        )
        XCTAssertFalse(
            upstream("space:com.example.forum?authority=*&action=create", stated: ["authority", "action"])
                .allowsSpace(exchange(type: "com.example.forum", authority: "did:plc:otherauthority"))
        )
    }

    /// Listing: a defaulted action suffices under upstream defaults; an
    /// unfiltered listing still needs a wildcard-type grant, as upstream.
    func testUpstreamDefaultsListingUsesDefaultedActions() {
        XCTAssertTrue(upstream("space:x.y.z").allowsSpaceListing(type: "x.y.z", authority: "did:plc:user"))
        XCTAssertFalse(permissions("space:x.y.z", stated: []).allowsSpaceListing(type: "x.y.z", authority: "did:plc:user"))
        XCTAssertFalse(upstream("space:x.y.z?authority=*").allowsSpaceListing(type: nil, authority: nil))
        XCTAssertTrue(upstream("space:*?authority=*").allowsSpaceListing(type: nil, authority: nil))
    }

    func testUpstreamDefaultsParticipateInEquality() {
        let scope = "space:x.y.z"
        XCTAssertNotEqual(permissions(scope, stated: []), upstream(scope))
        XCTAssertEqual(upstream(scope), upstream(scope))
    }
}
