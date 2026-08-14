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

    // MARK: - The delegation fence (§5.6.3)

    /// **The §9-D23 headline case.** The client requested
    /// `space:x.y.z?skey=*&action=read` — `authority` DEFAULTED, so the fence
    /// must refuse. Mint resolves `self` and persists the string below, in
    /// which all three values are literal. Re-parsing that string would make
    /// the fence flip false -> true. It must not, because provenance is read
    /// from the durable record, which still says `authority` was never stated.
    func testDelegationFenceRefusesAMintResolvedSelfAuthority() {
        let persisted = "space:x.y.z?authority=\(user)&skey=*&action=read"
        let permissions = permissions(persisted, stated: ["skey", "action"])
        XCTAssertFalse(permissions.allowsSpace(delegation(skey: "*")))
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

    /// Clause 1. A DEFAULTED action list contains `read` and must still refuse
    /// — this is the bare `space:<type>` shape §5.6.3 names as newly admitted
    /// by a naive `action.contains(.read)` port.
    func testDelegationFenceRefusesADefaultedActionList() {
        let bare = "space:x.y.z"
        XCTAssertFalse(
            permissions(bare, stated: []).allowsSpace(delegation(skey: "*"))
        )
    }

    /// Clause 1, value half: `action` must be exactly `[read]`, not merely
    /// contain it.
    func testDelegationFenceRefusesAStatedMultiActionGrant() {
        let scope = "space:x.y.z?authority=\(user)&skey=self&action=read&action=create"
        XCTAssertFalse(
            permissions(scope, stated: ["authority", "skey", "action"])
                .allowsSpace(delegation())
        )
    }

    /// Clause 2. A collection-qualified grant — INCLUDING `collection=*` — must
    /// never be amplifiable into a credential that reads every member
    /// repository (`SwanCore.swift:246-257`). Upstream permits exactly this
    /// (`space-permission.ts:104-107` takes the read arm before
    /// `collectionAllows`); Swan's refusal is the documented hardening.
    func testDelegationFenceRefusesAnyStatedCollection() {
        for collection in ["*", "app.bsky.feed.post"] {
            let scope = "space:x.y.z?authority=\(user)&skey=self&action=read&collection=\(collection)"
            XCTAssertFalse(
                permissions(scope, stated: ["authority", "skey", "action", "collection"])
                    .allowsSpace(delegation()),
                "collection=\(collection) must not be exchangeable"
            )
        }
    }

    /// Clause 3.
    func testDelegationFenceRefusesAStatedManageList() {
        let scope = "space:x.y.z?authority=\(user)&skey=self&action=read&manage=delete"
        XCTAssertFalse(
            permissions(scope, stated: ["authority", "skey", "action", "manage"])
                .allowsSpace(delegation())
        )
    }

    /// Clause 4, both halves.
    func testDelegationFenceRequiresBothAuthorityAndSkeyStated() {
        let scope = "space:x.y.z?authority=\(user)&skey=self&action=read"
        XCTAssertFalse(
            permissions(scope, stated: ["skey", "action"]).allowsSpace(delegation())
        )
        XCTAssertFalse(
            permissions(scope, stated: ["authority", "action"]).allowsSpace(delegation())
        )
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

    // MARK: - The aggregate-read hardening (§6.5.5)

    /// **This test fails under the literal §5.6.2 port, which is the point.**
    ///
    /// §5.6.2 originally declared `case read` with no payload and §5.6.3's arm
    /// was `return action.contains(.read)` — upstream's collection-INDEPENDENT
    /// rule (`space-permission.ts:104-110`, which takes the read arms *before*
    /// `collectionAllows` at `:112-115`). Ported literally, the second
    /// assertion below returns TRUE: a grant naming exactly one collection
    /// would satisfy a read that spans every collection, and the response would
    /// silently omit the rows the grant does not cover.
    ///
    /// That is the widening §6.5.5 exists to prevent
    /// (`SwanSpaces.swift:329-341`, "aggregate surfaces must not silently
    /// censor their response"). Nothing else in the suite catches it, because a
    /// collection-qualified read of *that same collection* — the first
    /// assertion — is legitimate and passes either way.
    func testAggregateReadRefusesACollectionQualifiedGrant() {
        let scope = "space:x.y.z?authority=\(user)&skey=self&action=read&collection=app.example.records"
        let permissions = permissions(
            scope,
            stated: ["authority", "skey", "action", "collection"]
        )

        // Reading that one collection is exactly what the grant names.
        XCTAssertTrue(
            permissions.allowsSpace(read(aggregate: false, collection: "app.example.records"))
        )
        // Reading ACROSS collections is not.
        XCTAssertFalse(
            permissions.allowsSpace(read(aggregate: true, collection: nil)),
            "a collection-qualified grant must not satisfy an aggregate read"
        )
        // Nor is a non-aggregate read of a DIFFERENT collection.
        XCTAssertFalse(
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

    /// The inverse: the same canonical string whose durable record says `skey`
    /// was NOT stated must refuse, even though the parsed value is `*` either way.
    func testListingFenceRefusesADefaultedWildcardSkey() {
        let canonical = "space:x.y.z?authority=\(user)&action=read"
        let permissions = permissions(canonical, stated: ["authority", "action"])
        XCTAssertFalse(permissions.allowsSpaceListing(type: "x.y.z", authority: user))
    }

    func testListingFenceRefusesADefaultedActionList() {
        let bare = "space:x.y.z"
        XCTAssertFalse(
            permissions(bare, stated: []).allowsSpaceListing(type: "x.y.z", authority: user)
        )
    }

    func testListingFenceRefusesAStatedCollectionOrManage() {
        let withCollection = "space:x.y.z?authority=\(user)&skey=*&action=read&collection=*"
        XCTAssertFalse(
            permissions(withCollection, stated: ["authority", "skey", "action", "collection"])
                .allowsSpaceListing(type: "x.y.z", authority: user)
        )
        let withManage = "space:x.y.z?authority=\(user)&skey=*&manage=update"
        XCTAssertFalse(
            permissions(withManage, stated: ["authority", "skey", "manage"])
                .allowsSpaceListing(type: "x.y.z", authority: user)
        )
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
