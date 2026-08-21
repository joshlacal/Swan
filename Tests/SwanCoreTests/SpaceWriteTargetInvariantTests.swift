import XCTest

@testable import SwanCore

/// The invariant that makes an action-less `space:` grant safe to admit.
///
/// ## Why this file exists
///
/// §9-D21 retires `isIssuableQualified`, so a `space:` grant naming no `action=`
/// is now admitted at PAR and minted into a durable token. `action` defaults to
/// `SPACE_DEFAULT_ACTIONS`, which **contains `create`, `update` and `delete`**
/// — so read as a list of verbs, such a grant looks like a whole-repository
/// write capability that no client ever asked for.
///
/// It is not one, and the reason is a single line: `collection` defaults to `[]`,
/// and the write arm of `matches(_:)` requires `collectionAllows(_:)`, which is
/// `contains(.any) || contains(.nsid(c))` — both false on an empty list, for
/// every collection. Upstream states the same rule as prose: "Empty means no
/// write targets, not 'all collections'" (`space-permission.ts:193-198`).
///
/// That refusal is load-bearing and, before this file, ungreppable: nothing in
/// the tree asserted it, and the admission layer deliberately does **not**
/// re-check it (§6.2's rule fires on a *stated* write action, because an
/// effective-set reading would also reject `manage=`-only grants and bare
/// `space:<type>`, both of which the spec requires be admitted).
///
/// ## The Phase-2 hazard this is positioned to catch
///
/// `withDefaultCollections` (§5.6.4 `expandSpaceCollections`) materialises a
/// grant's collections from the space's declared list. It is **not wired today**
/// — positive control: `grep -rn 'withDefaultCollections\|expandSpaceCollections'
/// Sources` returns only a doc-comment reference. The day it is, an
/// unstated-`action` grant gains collections and its *defaulted* write verbs go
/// live against every one of them, with no client having typed `create`. The
/// last test here pins that mechanism explicitly so the expansion cannot be
/// wired without someone reading it.
final class SpaceWriteTargetInvariantTests: XCTestCase {
    private let authority = "did:plc:abcdefghijklmnopqrstuvwx"
    private let spaceType = "app.example.doc"
    private let collection = "app.example.record"

    private func target(
        _ operation: SpaceScopeTarget.Operation,
        skey: String = "k"
    ) -> SpaceScopeTarget {
        SpaceScopeTarget(
            type: spaceType,
            authority: authority,
            skey: skey,
            operation: operation
        )
    }

    // MARK: the premise — the write verbs really are in the defaulted set

    func testAnUnstatedActionGrantCarriesTheDefaultedWriteVerbs() throws {
        let grant = try SpacePermission.parse("space:\(spaceType)?authority=\(authority)&skey=k")
        // If this ever stops being true the rest of this file is moot, and the
        // §6.2 analysis that justified keeping the `wasStated("action")` gate
        // needs redoing — so assert the premise rather than assuming it.
        XCTAssertEqual(Set(grant.action), Set(SPACE_DEFAULT_ACTIONS))
        XCTAssertTrue(grant.action.contains(.create))
        XCTAssertTrue(grant.action.contains(.update))
        XCTAssertTrue(grant.action.contains(.delete))
        XCTAssertTrue(grant.collection.isEmpty, "no collection was stated or defaulted in")
    }

    // MARK: the invariant — and it authorizes no write target

    func testAnUnstatedActionGrantAuthorizesNoWriteTarget() throws {
        let grant = try SpacePermission.parse("space:\(spaceType)?authority=\(authority)&skey=k")
        for verb in [SpaceScopeTarget.Operation.RecordWrite.create, .update, .delete] {
            XCTAssertFalse(
                grant.matches(target(.write(verb, collection: collection))),
                """
                A grant that named no `action=` must authorize no write, however \
                many write verbs the schema defaulted into it. The refusal comes \
                from `collectionAllows` on an empty collection list — NOT from \
                the admission layer, which deliberately admits this shape.
                """
            )
        }
    }

    func testABareSpaceGrantAuthorizesNoWriteTarget() throws {
        // The other shape that used to be refused at issuance by
        // `isIssuableQualified` and is now admitted and fenced instead.
        let grant = try SpacePermission.parse("space:\(spaceType)")
        XCTAssertFalse(grant.matches(target(.write(.create, collection: collection))))
        XCTAssertFalse(grant.matches(target(.write(.delete, collection: collection))))
    }

    func testAnUnstatedActionGrantIsStillAWorkingReadGrant() throws {
        // The refusal above must be specific to writes. If this fails, the
        // grant is inert rather than read-only and admitting it is pointless.
        let grant = try SpacePermission.parse("space:\(spaceType)?authority=\(authority)&skey=k")
        XCTAssertTrue(grant.matches(target(.read(aggregate: false, collection: nil))))
    }

    // MARK: the positive control — a collection is what activates a write

    func testAStatedCollectionIsWhatAuthorizesTheWrite() throws {
        // Without this, every assertion above would also pass if writes were
        // globally broken. This isolates the empty collection as the cause.
        let grant = try SpacePermission.parse(
            "space:\(spaceType)?authority=\(authority)&skey=k&action=create&collection=\(collection)"
        )
        XCTAssertTrue(grant.matches(target(.write(.create, collection: collection))))
        XCTAssertFalse(
            grant.matches(target(.write(.create, collection: "app.example.other"))),
            "a named collection authorizes that collection and no other"
        )
    }

    func testAWildcardCollectionAuthorizesAnyCollection() throws {
        let grant = try SpacePermission.parse(
            "space:\(spaceType)?authority=\(authority)&skey=k&action=create&collection=*"
        )
        XCTAssertTrue(grant.matches(target(.write(.create, collection: "anything.at.all"))))
    }

    // MARK: expansion supplies the TARGETS the empty collection list denied

    func testExpandingCollectionsActivatesTheDefaultedWrites() throws {
        // The resolution of the hazard this file was originally written to
        // name — and it is the opposite of what this file first asserted.
        //
        // `withDefaultCollections` is §5.6.4's `expandSpaceCollections`. The
        // rest of this file establishes that a bare grant authorizes no write
        // TARGET, because `collection` defaults to `[]`. That is a statement
        // about targets, not about verbs: the defaulted write verbs were
        // always present and always inert. Expansion supplies the targets, and
        // the verbs become live — which is the entire point of the step.
        //
        // A guard dropping those verbs when `action` was unstated was written
        // here and reverted. A schema default applies exactly when the client
        // did not state the parameter, so the guard made the
        // create/update/delete half of SPACE_DEFAULT_ACTIONS unreachable for
        // every grant that could exist. Upstream
        // (`space-permission.ts:134-146`) passes `action` through unchanged.
        //
        // Asserted through `.matches`, not by reading `expanded.action`: the
        // property that matters is what the grant AUTHORIZES.
        let grant = try SpacePermission.parse("space:\(spaceType)?authority=\(authority)&skey=k")
        XCTAssertFalse(grant.scopeParameters.wasStated("action"))
        // The premise: inert BEFORE expansion, purely for want of a target.
        for verb in [SpaceScopeTarget.Operation.RecordWrite.create, .update, .delete] {
            XCTAssertFalse(grant.matches(target(.write(verb, collection: collection))))
        }

        let expanded = grant.withDefaultCollections([.nsid(collection)])
        for verb in [SpaceScopeTarget.Operation.RecordWrite.create, .update, .delete] {
            XCTAssertTrue(
                expanded.matches(target(.write(verb, collection: collection))),
                """
                Expansion must materialise the space's declared collections as \
                write targets for the defaulted verbs. A token that cannot write \
                after expansion is narrower than the user consented to — §5.7.5(b).
                """
            )
        }
        // Bounded: only the declared collection, not everything.
        XCTAssertFalse(expanded.matches(target(.write(.create, collection: "com.other.undeclared"))))
    }

    func testExpansionStillProducesAUsableReadGrant() throws {
        // Expansion must materialise, not neuter. If this fails, expansion has
        // stopped producing a usable grant at all, and the write assertions in
        // the test above would be failing for that reason rather than for the
        // reason they name.
        let grant = try SpacePermission.parse("space:\(spaceType)?authority=\(authority)&skey=k")
        let expanded = grant.withDefaultCollections([.nsid(collection)])
        XCTAssertTrue(expanded.matches(target(.read(aggregate: false, collection: collection))))
        XCTAssertTrue(expanded.hasCollections, "the collections really were materialised")
    }

    func testExpansionPreservesAStatedWriteAction() throws {
        // A write the client DID state survives expansion untouched — the
        // narrowing counterpart to the test above, which covers the defaulted
        // case. Together they pin that `action` is passed through verbatim
        // regardless of provenance.
        //
        // Note this shape cannot reach expansion through Swan's own admission —
        // a stated write action with no collection is refused at PAR
        // (`OAuthScopeAdmissionError.writeActionWithoutCollection`). The control
        // is therefore about `withDefaultCollections`'s own contract, which is
        // what a future caller will rely on.
        let grant = try SpacePermission.parse(
            "space:\(spaceType)?authority=\(authority)&skey=k&action=create"
        )
        XCTAssertTrue(grant.scopeParameters.wasStated("action"))

        let expanded = grant.withDefaultCollections([.nsid(collection)])
        XCTAssertTrue(
            expanded.matches(target(.write(.create, collection: collection))),
            "a stated write action must survive expansion — `action` is passed through unchanged"
        )
    }

    func testExpansionPreservesAStatedReadOnlyAction() throws {
        // The realistic path: admission admits a stated collection-free READ, so
        // this is the stated-action shape expansion will actually meet. It must
        // stay read-only afterwards.
        let grant = try SpacePermission.parse(
            "space:\(spaceType)?authority=\(authority)&skey=k&action=read"
        )
        let expanded = grant.withDefaultCollections([.nsid(collection)])
        XCTAssertTrue(expanded.matches(target(.read(aggregate: false, collection: collection))))
        XCTAssertFalse(expanded.matches(target(.write(.create, collection: collection))))
    }
}
